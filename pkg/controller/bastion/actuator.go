// Copyright (c) 2021 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bastion

import (
	"encoding/json"
	"fmt"
	"net/http"

	openstackclient "github.com/gardener/gardener-extension-provider-openstack/pkg/openstack/client"

	"github.com/gardener/gardener/extensions/pkg/controller/bastion"
	"github.com/go-logr/logr"
	"github.com/gophercloud/gophercloud"
	computerfip "github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/floatingips"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/layer3/floatingips"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/rules"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// SSHPort is the default SSH Port used for bastion ingress firewall rule
	SSHPort = 22
)

type actuator struct {
	client                 client.Client
	openstackClientFactory openstackclient.FactoryFactory
	logger                 logr.Logger
}

// func newActuator(openstackClientFactory openstackclient.FactoryFactory) bastion.Actuator {
func newActuator(openstackClientFactory openstackclient.FactoryFactory) bastion.Actuator {
	return &actuator{
		openstackClientFactory: openstackClientFactory,
		logger:                 logger,
	}
}

func (a *actuator) InjectClient(client client.Client) error {
	a.client = client
	return nil
}

func getBastionInstance(openstackClientFactory openstackclient.Factory, name string) ([]servers.Server, error) {
	computerclient, err := openstackClientFactory.Compute()
	if err != nil {
		if ignoreNotFoundError(err) == nil {
			return nil, nil
		}
		return nil, err
	}
	return computerclient.FindServersByName(name)
}

func createBastionInstance(openstackClientFactory openstackclient.Factory, parameters servers.CreateOpts) (*servers.Server, error) {
	computerclient, err := openstackClientFactory.Compute()
	if err != nil {
		return nil, err
	}
	return computerclient.CreateServer(parameters)
}

func deleteBastionInstance(openstackClientFactory openstackclient.Factory, id string) error {
	computerclient, err := openstackClientFactory.Compute()
	if err != nil {
		return err
	}
	return computerclient.DeleteServer(id)
}

// GetIPs return privateip, publicip
func GetIPs(s *servers.Server, opt *Options) (string, string, error) {
	var privateIP, publicIp string

	type InstanceNic struct {
		MacAddr string `json:"OS-EXT-IPS-MAC:mac_addr"`
		Version int    `json:"version"`
		Addr    string `json:"addr"`
		Type    string `json:"OS-EXT-IPS:type"`
	}

	instanceNic := []InstanceNic{}

	if len(s.Addresses) == 0 {
		return "", "", fmt.Errorf("NIC not ready yet")
	}

	bytes, err := json.Marshal(s.Addresses[opt.ShootName])
	if err != nil {
		return "", "", err
	}
	err = json.Unmarshal(bytes, &instanceNic)
	if err != nil {
		return "", "", err
	}

	for i, v := range instanceNic {
		if v.Type == "fixed" {
			privateIP = instanceNic[i].Addr
		} else {
			publicIp = instanceNic[i].Addr
		}
	}

	return privateIP, publicIp, nil

}

func createFloatingIP(openstackClientFactory openstackclient.Factory, parameters floatingips.CreateOpts) (*floatingips.FloatingIP, error) {
	client, err := openstackClientFactory.Networking()
	if err != nil {
		return nil, err
	}
	return client.CreateFloatingIP(parameters)
}

func deleteFloatingIP(openstackClientFactory openstackclient.Factory, id string) error {
	client, err := openstackClientFactory.Networking()
	if err != nil {
		return err
	}
	return client.DeleteFloatingIP(id)
}

func associateFIPWithInstance(openstackClientFactory openstackclient.Factory, id string, parameter computerfip.AssociateOpts) error {
	client, err := openstackClientFactory.Compute()
	if err != nil {
		return err
	}
	return client.AssociateFIPWithInstance(id, parameter)
}

func findFloatingIDbyInstnaceID(openstackClientFactory openstackclient.Factory, id string) (string, error) {
	client, err := openstackClientFactory.Compute()
	if err != nil {
		return "", err
	}
	return client.FindFloatingIDbyInstnaceID(id)
}

func getExternalNetworkInfoByName(openstackClientFactory openstackclient.Factory, name string) ([]networks.Network, error) {
	client, err := openstackClientFactory.Networking()
	if err != nil {
		return nil, err
	}
	return client.GetExternalNetworkInfoByName(name)

}

func getFipbyName(openstackClientFactory openstackclient.Factory, name string) ([]floatingips.FloatingIP, error) {
	client, err := openstackClientFactory.Networking()
	if err != nil {
		if ignoreNotFoundError(err) == nil {
			return nil, nil
		}
		return nil, err
	}
	return client.GetFipbyName(name)
}

func ignoreNotFoundError(err error) error {
	if err == nil {
		return nil
	}

	if e, ok := err.(gophercloud.ErrDefault404); ok && e.Actual == http.StatusNotFound {
		return nil
	}

	return err
}

func createSecurityGroup(openstackClientFactory openstackclient.Factory, createOpts groups.CreateOpts) (*groups.SecGroup, error) {
	client, err := openstackClientFactory.Networking()
	if err != nil {
		return nil, err
	}
	return client.CreateSecurityGroup(createOpts)
}

func deleteSecurityGroup(openstackClientFactory openstackclient.Factory, groupid string) error {
	client, err := openstackClientFactory.Networking()
	if err != nil {
		return err
	}
	return client.DeleteSecurityGroup(groupid)
}

func getSecurityGroupId(openstackClientFactory openstackclient.Factory, name string) ([]groups.SecGroup, error) {
	client, err := openstackClientFactory.Networking()
	if err != nil {
		return nil, err
	}
	return client.GetSecurityGroupbyName(name)
}

func createRules(openstackClientFactory openstackclient.Factory, createOpts rules.CreateOpts) (*rules.SecGroupRule, error) {
	client, err := openstackClientFactory.Networking()
	if err != nil {
		return nil, err
	}
	return client.CreateRule(createOpts)
}
