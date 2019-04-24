// Copyright 2019 Authors of Cilium
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

package awscni

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/logging/logfields"
	chainingapi "github.com/cilium/cilium/plugins/cilium-cni/chaining/api"

	cniTypesVer "github.com/containernetworking/cni/pkg/types/current"
	cniVersion "github.com/containernetworking/cni/pkg/version"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type awscniChainer struct{}

func (f *awscniChainer) Add(ctx context.Context, pluginCtx chainingapi.PluginContext) (res *cniTypesVer.Result, err error) {
	err = cniVersion.ParsePrevResult(&pluginCtx.NetConf.NetConf)
	if err != nil {
		err = fmt.Errorf("unable to understand network config: %s", err)
		return
	}

	var prevRes *cniTypesVer.Result
	prevRes, err = cniTypesVer.NewResultFromResult(pluginCtx.NetConf.PrevResult)
	if err != nil {
		err = fmt.Errorf("unable to get previous network result: %s", err)
		return
	}

	defer func() {
		if err != nil {
			pluginCtx.Logger.WithError(err).
				WithFields(logrus.Fields{"cni-pre-result": pluginCtx.NetConf.PrevResult.String()}).
				Errorf("Unable to create endpoint")
		}
	}()
	var (
		hostMac, vethHostName, vethLXCMac, vethIP string
		vethHostIdx                               int
	)

	if len(prevRes.IPs) != 1 {
		err = fmt.Errorf("more than 1 IP provided in result from aws-cni")
		return
	}

	var routes []netlink.Route
	routes, err = netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		err = fmt.Errorf("unable to list routes: %s", err)
		return
	}

	for _, r := range routes {
		if r.Dst == nil {
			continue
		}

		aMaskLen, aMaskBits := r.Dst.Mask.Size()
		bMaskLen, bMaskBits := prevRes.IPs[0].Address.Mask.Size()
		if aMaskLen != bMaskLen || aMaskBits != bMaskBits || !r.Dst.IP.Equal(prevRes.IPs[0].Address.IP) {
			continue
		}

		var link netlink.Link
		link, err = netlink.LinkByIndex(r.LinkIndex)
		if err != nil {
			err = fmt.Errorf("unable to lookup link with ifindex %d: %s", r.LinkIndex, err)
			return
		}

		vethHostName = link.Attrs().Name
		vethHostIdx = link.Attrs().Index
		vethIP = r.Dst.IP.String()
		hostMac = link.Attrs().HardwareAddr.String()

		veth, ok := link.(*netlink.Veth)
		if !ok {
			err = fmt.Errorf("link %s is not a veth interface", vethHostName)
			return
		}

		var peerIndex int
		peerIndex, err = netlink.VethPeerIndex(veth)
		if err != nil {
			err = fmt.Errorf("unable to retrieve index of veth peer %s: %s", vethHostName, err)
			return
		}

		var peer netlink.Link
		peer, err = netlink.LinkByIndex(peerIndex)
		if err != nil {
			err = fmt.Errorf("unable to lookup link %s: %s", veth.PeerName, err)
			return
		}

		vethLXCMac = peer.Attrs().HardwareAddr.String()
	}

	switch {
	case vethHostName == "":
		err = errors.New("unable to determine name of veth pair on the host side")
		return
	case vethLXCMac == "":
		err = errors.New("unable to determine MAC address of veth pair on the container side")
		return
	case vethIP == "":
		err = errors.New("unable to determine IP address of the container")
		return
	case vethHostIdx == 0:
		err = errors.New("unable to determine index interface of veth pair on the host side")
		return
	}

	ep := &models.EndpointChangeRequest{
		Addressing: &models.AddressPair{
			IPV4: vethIP,
		},
		ContainerID:       pluginCtx.Args.ContainerID,
		State:             models.EndpointStateWaitingForIdentity,
		HostMac:           hostMac,
		InterfaceIndex:    int64(vethHostIdx),
		Mac:               vethLXCMac,
		InterfaceName:     vethHostName,
		K8sPodName:        string(pluginCtx.CniArgs.K8S_POD_NAME),
		K8sNamespace:      string(pluginCtx.CniArgs.K8S_POD_NAMESPACE),
		SyncBuildEndpoint: true,
		DatapathConfiguration: &models.EndpointDatapathConfiguration{
			// aws-cni requires ARP passthrough between Linux and
			// the pod
			RequireArpPassthrough: true,

			// The route is pointing directly into the veth of the
			// pod, install a host-facing egress program to
			// implement ingress policy and to provide reverse NAT
			RequireEgressProg: true,

			// The IP is managed by the aws-cni plugin, no need for
			// Cilium to manage any aspect of addressing
			ExternalIPAM: true,

			// All routing is performed by the Linux stack
			DisableRouting: true,
		},
	}

	err = pluginCtx.Client.EndpointCreate(ep)
	if err != nil {
		pluginCtx.Logger.WithError(err).WithFields(logrus.Fields{
			logfields.ContainerID: ep.ContainerID}).Warn("Unable to create endpoint")
		err = fmt.Errorf("unable to create endpoint: %s", err)
		return
	}

	pluginCtx.Logger.WithFields(logrus.Fields{
		logfields.ContainerID: ep.ContainerID}).Debug("Endpoint successfully created")

	res = &cniTypesVer.Result{
		IPs: prevRes.IPs,
	}

	return
}

func init() {
	chainingapi.Register("aws-cni", &awscniChainer{})
}
