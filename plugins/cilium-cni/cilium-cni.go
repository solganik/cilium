// Copyright 2016-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint/connector"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/uuid"
	"github.com/cilium/cilium/pkg/version"

	"github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniTypesVer "github.com/containernetworking/cni/pkg/types/current"
	cniVersion "github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"golang.org/x/sys/unix"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "cilium-cni")
)

func init() {
	logging.SetLogLevel(logrus.DebugLevel)
	runtime.LockOSThread()
}

type CmdState struct {
	Endpoint  *models.EndpointChangeRequest
	IP6       addressing.CiliumIPv6
	IP6routes []route.Route
	IP4       addressing.CiliumIPv4
	IP4routes []route.Route
	Client    *client.Client
	HostAddr  *models.NodeAddressing
}

type netConf struct {
	cniTypes.NetConf
	MTU  int  `json:"mtu"`
	Args Args `json:"args"`
}

type cniArgsSpec struct {
	cniTypes.CommonArgs
	IP                         net.IP
	K8S_POD_NAME               cniTypes.UnmarshallableString
	K8S_POD_NAMESPACE          cniTypes.UnmarshallableString
	K8S_POD_INFRA_CONTAINER_ID cniTypes.UnmarshallableString
}

// Args contains arbitrary information a scheduler
// can pass to the cni plugin
type Args struct {
	Mesos Mesos `json:"org.apache.mesos,omitempty"`
}

// Mesos contains network-specific information from the scheduler to the cni plugin
type Mesos struct {
	NetworkInfo NetworkInfo `json:"network_info"`
}

// NetworkInfo supports passing only labels from mesos
type NetworkInfo struct {
	Name   string `json:"name"`
	Labels struct {
		Labels []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"labels,omitempty"`
	} `json:"labels,omitempty"`
}

func main() {
	skel.PluginMain(cmdAdd,
		nil,
		cmdDel,
		cniVersion.PluginSupports("0.1.0", "0.2.0", "0.3.0", "0.3.1"),
		"Cilium CNI plugin "+version.Version)
}

func ipv6IsEnabled(ipam *models.IPAMResponse) bool {
	if ipam == nil || ipam.Address.IPV6 == "" {
		return false
	}

	if ipam.HostAddressing != nil && ipam.HostAddressing.IPV6 != nil {
		return ipam.HostAddressing.IPV6.Enabled
	}

	return true
}

func ipv4IsEnabled(ipam *models.IPAMResponse) bool {
	if ipam == nil || ipam.Address.IPV4 == "" {
		return false
	}

	if ipam.HostAddressing != nil && ipam.HostAddressing.IPV4 != nil {
		return ipam.HostAddressing.IPV4.Enabled
	}

	return true
}

func loadNetConf(bytes []byte) (*netConf, string, error) {
	n := &netConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, "", fmt.Errorf("failed to load netconf: %s", err)
	}
	return n, n.CNIVersion, nil
}

func releaseIP(client *client.Client, ip string) {
	if ip != "" {
		if err := client.IPAMReleaseIP(ip); err != nil {
			log.WithError(err).WithField(logfields.IPAddr, ip).Warn("Unable to release IP")
		}
	}
}

func releaseIPs(client *client.Client, addr *models.AddressPair) {
	releaseIP(client, addr.IPV6)
	releaseIP(client, addr.IPV4)
}

func addIPConfigToLink(ip addressing.CiliumIP, routes []route.Route, link netlink.Link, ifName string) error {
	log.WithFields(logrus.Fields{
		logfields.IPAddr:    ip,
		"netLink":           logfields.Repr(link),
		logfields.Interface: ifName,
	}).Debug("Configuring link")

	addr := &netlink.Addr{IPNet: ip.EndpointPrefix()}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("failed to add addr to %q: %v", ifName, err)
	}

	// ipvlan needs to be UP before we add routes, and can only be UPed after
	// we added an IP address.
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set %q UP: %v", ifName, err)
	}

	// Sort provided routes to make sure we apply any more specific
	// routes first which may be used as nexthops in wider routes
	sort.Sort(route.ByMask(routes))

	for _, r := range routes {
		log.WithField("route", logfields.Repr(r)).Debug("Adding route")
		rt := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Scope:     netlink.SCOPE_UNIVERSE,
			Dst:       &r.Prefix,
			MTU:       r.MTU,
		}

		if r.Nexthop == nil {
			rt.Scope = netlink.SCOPE_LINK
		} else {
			rt.Gw = *r.Nexthop
		}

		if err := netlink.RouteAdd(rt); err != nil {
			if !os.IsExist(err) {
				return fmt.Errorf("failed to add route '%s via %v dev %v': %v",
					r.Prefix.String(), r.Nexthop, ifName, err)
			}
		}
	}

	return nil
}

func configureIface(ipam *models.IPAMResponse, ifName string, state *CmdState) (string, error) {
	l, err := netlink.LinkByName(ifName)
	if err != nil {
		return "", fmt.Errorf("failed to lookup %q: %v", ifName, err)
	}

	if err := netlink.LinkSetUp(l); err != nil {
		return "", fmt.Errorf("failed to set %q UP: %v", ifName, err)
	}

	if ipv4IsEnabled(ipam) {
		if err := addIPConfigToLink(state.IP4, state.IP4routes, l, ifName); err != nil {
			return "", fmt.Errorf("error configuring IPv4: %s", err.Error())
		}
	}

	if ipv6IsEnabled(ipam) {
		if err := addIPConfigToLink(state.IP6, state.IP6routes, l, ifName); err != nil {
			return "", fmt.Errorf("error configuring IPv6: %s", err.Error())
		}
	}

	if err := netlink.LinkSetUp(l); err != nil {
		return "", fmt.Errorf("failed to set %q UP: %v", ifName, err)
	}

	if l.Attrs() != nil {
		return l.Attrs().HardwareAddr.String(), nil
	}

	return "", nil
}

func newCNIRoute(r route.Route) *cniTypes.Route {
	rt := &cniTypes.Route{
		Dst: r.Prefix,
	}
	if r.Nexthop != nil {
		rt.GW = *r.Nexthop
	}

	return rt
}

func prepareIP(ipAddr string, isIPv6 bool, state *CmdState, mtu int) (*cniTypesVer.IPConfig, []*cniTypes.Route, error) {
	var (
		routes    []route.Route
		err       error
		gw        string
		ipVersion string
		ip        addressing.CiliumIP
	)

	if isIPv6 {
		if state.IP6, err = addressing.NewCiliumIPv6(ipAddr); err != nil {
			return nil, nil, err
		}
		if state.IP6routes, err = connector.IPv6Routes(state.HostAddr, mtu); err != nil {
			return nil, nil, err
		}
		routes = state.IP6routes
		ip = state.IP6
		gw = connector.IPv6Gateway(state.HostAddr)
		ipVersion = "6"
	} else {
		if state.IP4, err = addressing.NewCiliumIPv4(ipAddr); err != nil {
			return nil, nil, err
		}
		if state.IP4routes, err = connector.IPv4Routes(state.HostAddr, mtu); err != nil {
			return nil, nil, err
		}
		routes = state.IP4routes
		ip = state.IP4
		gw = connector.IPv4Gateway(state.HostAddr)
		ipVersion = "4"
	}

	rt := []*cniTypes.Route{}
	for _, r := range routes {
		rt = append(rt, newCNIRoute(r))
	}

	gwIP := net.ParseIP(gw)
	if gwIP == nil {
		return nil, nil, fmt.Errorf("Invalid gateway address: %s", gw)
	}

	return &cniTypesVer.IPConfig{
		Address: *ip.EndpointPrefix(),
		Gateway: gwIP,
		Version: ipVersion,
	}, rt, nil
}

func setUPWithFlannel(logger *logrus.Entry, args *skel.CmdArgs, cniArgs cniArgsSpec, n *netConf, cniVer string, c *client.Client) (err error) {
	err = cniVersion.ParsePrevResult(&n.NetConf)
	if err != nil {
		return fmt.Errorf("unable to understand network config: %s", err)
	}
	r, err := cniTypesVer.GetResult(n.PrevResult)
	if err != nil {
		return fmt.Errorf("unable to get previous network result: %s", err)
	}
	// We only care about the veth interface that is on the host side
	// and cni0. Interfaces should be similar as:
	//       "interfaces":[
	//         {
	//            "name":"cni0",
	//            "mac":"0a:58:0a:f4:00:01"
	//         },
	//         {
	//            "name":"veth15707e9b",
	//            "mac":"4e:6d:93:35:6b:45"
	//         },
	//         {
	//            "name":"eth0",
	//            "mac":"0a:58:0a:f4:00:06",
	//            "sandbox":"/proc/15259/ns/net"
	//         }
	//       ]

	defer func() {
		if err != nil {
			logger.WithError(err).
				WithFields(logrus.Fields{"cni-pre-result": n.PrevResult.String()}).
				Errorf("Unable to create endpoint")
		}
	}()
	var (
		hostMac, vethHostName, vethLXCMac, vethIP string
		vethHostIdx, vethSliceIdx                 int
	)
	for i, iDev := range r.Interfaces {
		// We only care about the veth interface mac address on the container side.
		if iDev.Sandbox != "" {
			vethLXCMac = iDev.Mac
			vethSliceIdx = i
			continue
		}

		l, err := netlink.LinkByName(iDev.Name)
		if err != nil {
			continue
		}
		switch l.Type() {
		case "veth":
			vethHostName = iDev.Name
			vethHostIdx = l.Attrs().Index
		case "bridge":
			// likely to be cni0
			hostMac = iDev.Mac
		}
	}
	for _, ipCfg := range r.IPs {
		if ipCfg.Interface != nil && *ipCfg.Interface == vethSliceIdx {
			vethIP = ipCfg.Address.IP.String()
			break
		}
	}
	switch {
	case hostMac == "":
		return errors.New("unable to determine MAC address of bridge interface (cni0)")
	case vethHostName == "":
		return errors.New("unable to determine name of veth pair on the host side")
	case vethLXCMac == "":
		return errors.New("unable to determine MAC address of veth pair on the container side")
	case vethIP == "":
		return errors.New("unable to determine IP address of the container")
	case vethHostIdx == 0:
		return errors.New("unable to determine index interface of veth pair on the host side")
	}

	ep := &models.EndpointChangeRequest{
		Addressing: &models.AddressPair{
			IPV4: vethIP,
		},
		ContainerID:       args.ContainerID,
		State:             models.EndpointStateWaitingForIdentity,
		HostMac:           hostMac,
		InterfaceIndex:    int64(vethHostIdx),
		Mac:               vethLXCMac,
		InterfaceName:     vethHostName,
		K8sPodName:        string(cniArgs.K8S_POD_NAME),
		K8sNamespace:      string(cniArgs.K8S_POD_NAMESPACE),
		SyncBuildEndpoint: true,
	}

	err = c.EndpointCreate(ep)
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{
			logfields.ContainerID: ep.ContainerID}).Warn("Unable to create endpoint")
		err = fmt.Errorf("unable to create endpoint: %s", err)
		return
	}

	logger.WithFields(logrus.Fields{
		logfields.ContainerID: ep.ContainerID}).Debug("Endpoint successfully created")
	return nil
}

func cmdAdd(args *skel.CmdArgs) (err error) {
	var (
		ipConfig *cniTypesVer.IPConfig
		routes   []*cniTypes.Route
		ipam     *models.IPAMResponse
		n        *netConf
		cniVer   string
		c        *client.Client
		netNs    ns.NetNS
	)

	logger := log.WithField("eventUUID", uuid.NewUUID())
	logger.WithField("args", args).Debug("Processing CNI ADD request")

	n, cniVer, err = loadNetConf(args.StdinData)
	if err != nil {
		return
	}

	cniArgs := cniArgsSpec{}
	if err = cniTypes.LoadArgs(args.Args, &cniArgs); err != nil {
		err = fmt.Errorf("unable to extract CNI arguments: %s", err)
		return
	}

	c, err = client.NewDefaultClientWithTimeout(defaults.ClientConnectTimeout)
	if err != nil {
		err = fmt.Errorf("unable to connect to Cilium daemon: %s", err)
		return
	}

	if len(n.NetConf.RawPrevResult) != 0 {
		switch n.Name {
		case "cbr0":
			err = setUPWithFlannel(logger, args, cniArgs, n, cniVer, c)
			if err != nil {
				return
			}
			return cniTypes.PrintResult(&cniTypesVer.Result{}, cniVer)
		default:
		}
	}

	netNs, err = ns.GetNS(args.Netns)
	if err != nil {
		err = fmt.Errorf("failed to open netns %q: %s", args.Netns, err)
	}
	defer netNs.Close()

	if err = netns.RemoveIfFromNetNSIfExists(netNs, args.IfName); err != nil {
		err = fmt.Errorf("failed removing interface %q from namespace %q: %s",
			args.IfName, args.Netns, err)
		return
	}

	addLabels := models.Labels{}

	for _, label := range n.Args.Mesos.NetworkInfo.Labels.Labels {
		addLabels = append(addLabels, fmt.Sprintf("%s:%s=%s", labels.LabelSourceMesos, label.Key, label.Value))
	}

	configResult, err := c.ConfigGet()
	if err != nil {
		return fmt.Errorf("unable to retrieve configuration from cilium-agent: %s", err)
	}

	if configResult == nil || configResult.Status == nil {
		err = fmt.Errorf("did not receive configuration from cilium-agent")
		return
	}

	conf := *configResult.Status

	ep := &models.EndpointChangeRequest{
		ContainerID:  args.ContainerID,
		Labels:       addLabels,
		State:        models.EndpointStateWaitingForIdentity,
		Addressing:   &models.AddressPair{},
		K8sPodName:   string(cniArgs.K8S_POD_NAME),
		K8sNamespace: string(cniArgs.K8S_POD_NAMESPACE),
	}

	switch conf.DatapathMode {
	case option.DatapathModeVeth:
		var (
			veth      *netlink.Veth
			peer      *netlink.Link
			tmpIfName string
		)
		veth, peer, tmpIfName, err = connector.SetupVeth(ep.ContainerID, int(conf.DeviceMTU), ep)
		if err != nil {
			return err
		}
		defer func() {
			if err != nil {
				if err = netlink.LinkDel(veth); err != nil {
					logger.WithError(err).WithField(logfields.Veth, veth.Name).Warn("failed to clean up and delete veth")
				}
			}
		}()

		if err = netlink.LinkSetNsFd(*peer, int(netNs.Fd())); err != nil {
			err = fmt.Errorf("unable to move veth pair '%v' to netns: %s", peer, err)
			return
		}

		_, _, err = connector.SetupVethRemoteNs(netNs, tmpIfName, args.IfName)
		if err != nil {
			return
		}
	case option.DatapathModeIpvlan:
		ipvlanConf := *conf.IpvlanConfiguration
		index := int(ipvlanConf.MasterDeviceIndex)

		var mapFD int
		mapFD, err = connector.CreateAndSetupIpvlanSlave(
			ep.ContainerID, args.IfName, netNs,
			int(conf.DeviceMTU), index, ipvlanConf.OperationMode, ep,
		)
		if err != nil {
			return
		}
		defer unix.Close(mapFD)
	}

	podName := string(cniArgs.K8S_POD_NAMESPACE) + "/" + string(cniArgs.K8S_POD_NAME)
	ipam, err = c.IPAMAllocate("", podName)
	if err != nil {
		return
	}

	if ipam.Address == nil {
		err = fmt.Errorf("Invalid IPAM response, missing addressing")
		return
	}

	// release addresses on failure
	defer func() {
		if err != nil {
			releaseIP(c, ipam.Address.IPV4)
			releaseIP(c, ipam.Address.IPV6)
		}
	}()

	if err = connector.SufficientAddressing(ipam.HostAddressing); err != nil {
		return
	}

	state := CmdState{
		Endpoint: ep,
		Client:   c,
		HostAddr: ipam.HostAddressing,
	}

	res := &cniTypesVer.Result{}

	if !ipv6IsEnabled(ipam) && !ipv4IsEnabled(ipam) {
		err = fmt.Errorf("IPAM did not provide IPv4 or IPv6 address")
		return
	}

	if ipv6IsEnabled(ipam) {
		ep.Addressing.IPV6 = ipam.Address.IPV6

		ipConfig, routes, err = prepareIP(ep.Addressing.IPV6, true, &state, int(conf.RouteMTU))
		if err != nil {
			return
		}
		res.IPs = append(res.IPs, ipConfig)
		res.Routes = append(res.Routes, routes...)
	}

	if ipv4IsEnabled(ipam) {
		ep.Addressing.IPV4 = ipam.Address.IPV4

		ipConfig, routes, err = prepareIP(ep.Addressing.IPV4, false, &state, int(conf.RouteMTU))
		if err != nil {
			return
		}
		res.IPs = append(res.IPs, ipConfig)
		res.Routes = append(res.Routes, routes...)
	}

	var macAddrStr string
	if err = netNs.Do(func(_ ns.NetNS) error {
		allInterfacesPath := filepath.Join("/proc", "sys", "net", "ipv6", "conf", "all", "disable_ipv6")
		err = connector.WriteSysConfig(allInterfacesPath, "0\n")
		if err != nil {
			logger.WithError(err).Warn("unable to enable ipv6 on all interfaces")
		}
		macAddrStr, err = configureIface(ipam, args.IfName, &state)
		return err
	}); err != nil {
		return
	}

	res.Interfaces = append(res.Interfaces, &cniTypesVer.Interface{
		Name:    args.IfName,
		Mac:     macAddrStr,
		Sandbox: "/proc/" + args.Netns + "/ns/net",
	})

	// Specify that endpoint must be regenerated synchronously. See GH-4409.
	ep.SyncBuildEndpoint = true
	if err = c.EndpointCreate(ep); err != nil {
		logger.WithError(err).WithFields(logrus.Fields{
			logfields.ContainerID: ep.ContainerID}).Warn("Unable to create endpoint")
		err = fmt.Errorf("Unable to create endpoint: %s", err)
		return
	}

	logger.WithFields(logrus.Fields{
		logfields.ContainerID: ep.ContainerID}).Debug("Endpoint successfully created")
	return cniTypes.PrintResult(res, cniVer)
}

func cmdDel(args *skel.CmdArgs) error {
	// Note about when to return errors: kubelet will retry the deletion
	// for a long time. Therefore, only return an error for errors which
	// are guaranteed to be recoverable.
	log.WithField("args", args).Debug("Processing CNI DEL request")

	c, err := client.NewDefaultClientWithTimeout(defaults.ClientConnectTimeout)
	if err != nil {
		// this error can be recovered from
		return fmt.Errorf("unable to connect to Cilium daemon: %s", err)
	}

	id := endpointid.NewID(endpointid.ContainerIdPrefix, args.ContainerID)
	if err := c.EndpointDelete(id); err != nil {
		// EndpointDelete returns an error in the following scenarios:
		// DeleteEndpointIDInvalid: Invalid delete parameters, no need to retry
		// DeleteEndpointIDNotFound: No need to retry
		// DeleteEndpointIDErrors: Errors encountered while deleting,
		//                         the endpoint is always deleted though, no
		//                         need to retry
		// ClientError: Various reasons, type will be ClientError and
		//              Recoverable() will return true if error can be
		//              retried
		log.WithError(err).Warning("Errors encountered while deleting endpoint")
		if clientError, ok := err.(client.ClientError); ok {
			if clientError.Recoverable() {
				return err
			}
		}
	}

	netNs, err := ns.GetNS(args.Netns)
	if err != nil {
		log.WithError(err).Warningf("Unable to enter namespace %q, will not delete interface", args.Netns)
		// We are not returning an error as this is very unlikely to be recoverable
		return nil
	}
	defer netNs.Close()

	err = netns.RemoveIfFromNetNSIfExists(netNs, args.IfName)
	if err != nil {
		log.WithError(err).Warningf("Unable to delete interface %s in namespace %q, will not delete interface", args.IfName, args.Netns)
		// We are not returning an error as this is very unlikely to be recoverable
	}

	return nil
}
