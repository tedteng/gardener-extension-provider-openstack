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
	"context"
	"fmt"
	"time"

	"github.com/gardener/gardener-extension-provider-openstack/pkg/openstack"
	openstackclient "github.com/gardener/gardener-extension-provider-openstack/pkg/openstack/client"

	"github.com/gardener/gardener/extensions/pkg/controller"
	ctrlerror "github.com/gardener/gardener/extensions/pkg/controller/error"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/go-logr/logr"
	"github.com/gophercloud/gophercloud"
	computefip "github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/floatingips"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/layer3/floatingips"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/groups"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/rules"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// bastionEndpoints holds the endpoints the bastion host provides
type bastionEndpoints struct {
	// private is the private endpoint of the bastion. It is required when opening a port on the worker node to allow SSH access from the bastion
	private *corev1.LoadBalancerIngress
	//  public is the public endpoint where the enduser connects to establish the SSH connection.
	public *corev1.LoadBalancerIngress
}

// Ready returns true if both public and private interfaces each have either
// an IP or a hostname or both.
func (be *bastionEndpoints) Ready() bool {
	return be != nil && IngressReady(be.private) && IngressReady(be.public)
}

func (a *actuator) Reconcile(ctx context.Context, bastion *extensionsv1alpha1.Bastion, cluster *controller.Cluster) error {
	logger := a.logger.WithValues("bastion", client.ObjectKeyFromObject(bastion), "operation", "reconcile")

	opt, err := DetermineOptions(bastion, cluster)
	if err != nil {
		return err
	}

	credentials, err := openstack.GetCredentials(ctx, a.client, opt.SecretReference, false)
	if err != nil {
		return fmt.Errorf("could not get Openstack credentials: %w", err)
	}

	openstackClientFactory, err := a.openstackClientFactory.NewFactory(credentials)
	if err != nil {
		return fmt.Errorf("could not create Openstack client factory: %w", err)
	}

	securityGroup, err := ensureSecurityGroup(openstackClientFactory, opt)
	if err != nil {
		return err
	}

	err = ensureSecurityGroupRules(openstackClientFactory, opt, securityGroup.ID)
	if err != nil {
		return err
	}

	instance, err := ensureComputeInstance(logger, openstackClientFactory, opt)
	if err != nil || instance == nil {
		return err
	}

	fipid, err := ensurePublicIPAddress(opt, openstackClientFactory)
	if err != nil {
		return err
	}

	ready, err := ensureAssociateFIPWithInstance(openstackClientFactory, instance, fipid)
	if err != nil || !ready {
		return err
	}

	// refresh instance after public ip attached/created
	instances, err := getBastionInstance(openstackClientFactory, opt.BastionInstanceName)
	if openstackclient.IgnoreNotFoundError(err) != nil {
		return err
	}

	if len(instances) != 0 {
		return err
	}

	// check if the instance already exists and has an IP
	endpoints, err := getInstanceEndpoints(&instances[0], opt)
	if err != nil {
		return err
	}

	if !endpoints.Ready() {
		return &ctrlerror.RequeueAfterError{
			// requeue rather soon, so that the user (most likely gardenctl eventually)
			// doesn't have to wait too long for the public endpoint to become available
			RequeueAfter: 5 * time.Second,
			Cause:        fmt.Errorf("bastion instance has no public/private endpoints yet"),
		}
	}

	// once a public endpoint is available, publish the endpoint on the
	// Bastion resource to notify upstream about the ready instance
	return controller.TryUpdateStatus(ctx, retry.DefaultBackoff, a.client, bastion, func() error {
		bastion.Status.Ingress = *endpoints.public
		return nil
	})
}

func ensurePublicIPAddress(opt *Options, openstackClientFactory openstackclient.Factory) (*floatingips.FloatingIP, error) {
	fips, err := getFipByName(openstackClientFactory, opt.BastionInstanceName)
	if err != nil {
		return nil, err
	}

	if fips != nil && fips[0].Status == "ACTIVE" {
		return &fips[0], nil
	}

	logger.Info("creating new bastion Public IP")

	externalFipInfo, err := getExternalNetworkInfoByName(openstackClientFactory, opt.FloatingPoolName)
	if err != nil {
		return nil, err
	}

	createOpts := floatingips.CreateOpts{
		FloatingNetworkID: externalFipInfo[0].ID,
		Description:       opt.BastionInstanceName,
	}

	fip, err := createFloatingIP(openstackClientFactory, createOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to get (create) public ip address: %w", err)
	}

	return fip, nil
}

func ensureComputeInstance(logger logr.Logger, openstackClientFactory openstackclient.Factory, opt *Options) (*servers.Server, error) {
	instances, err := getBastionInstance(openstackClientFactory, opt.BastionInstanceName)
	if openstackclient.IgnoreNotFoundError(err) != nil {
		return nil, err
	}

	if len(instances) != 0 {
		return &instances[0], err
	}

	logger.Info("Creating new bastion compute instance")

	networkingClient, err := openstackClientFactory.Networking()
	if err != nil {
		return nil, err
	}

	networkInfo, err := networkingClient.GetNetworkByName(opt.ShootName)
	if err != nil {
		return nil, err
	}

	createOpts := servers.CreateOpts{
		Name:           opt.BastionInstanceName,
		FlavorRef:      opt.FlavorRef,
		ImageRef:       opt.ImageRef,
		SecurityGroups: []string{opt.SecurityGroup},
		Networks:       []servers.Network{{UUID: networkInfo[0].ID}},
		UserData:       opt.UserData,
	}

	instance, err := createBastionInstance(openstackClientFactory, createOpts)
	if err != nil {
		return nil, fmt.Errorf("%w, failed to create bastion compute instance", err)
	}

	if instance != nil {
		return instance, err
	}

	return nil, fmt.Errorf("%w, failed to get / create bastion compute instance", err)
}

func getInstanceEndpoints(instance *servers.Server, opt *Options) (*bastionEndpoints, error) {
	if instance == nil {
		return nil, fmt.Errorf("compute instance can't be nil")
	}

	if instance.Status != "ACTIVE" {
		return nil, fmt.Errorf("compute instance not active yet")
	}

	endpoints := &bastionEndpoints{}

	privateIP, externalIP, err := GetIPs(instance, opt)
	if err != nil {
		return nil, fmt.Errorf("no IP found: %w", err)
	}

	if ingress := addressToIngress(nil, &privateIP); ingress != nil {
		endpoints.private = ingress
	}

	if ingress := addressToIngress(nil, &externalIP); ingress != nil {
		endpoints.public = ingress
	}
	return endpoints, nil
}

// IngressReady returns true if either an IP or a hostname or both are set.
func IngressReady(ingress *corev1.LoadBalancerIngress) bool {
	return ingress != nil && (ingress.Hostname != "" || ingress.IP != "")
}

// addressToIngress converts the IP address into a
// corev1.LoadBalancerIngress resource. If both arguments are nil, then
// nil is returned.
func addressToIngress(dnsName *string, ipAddress *string) *corev1.LoadBalancerIngress {
	var ingress *corev1.LoadBalancerIngress

	if ipAddress != nil || dnsName != nil {
		ingress = &corev1.LoadBalancerIngress{}
		if dnsName != nil {
			ingress.Hostname = *dnsName
		}

		if ipAddress != nil {
			ingress.IP = *ipAddress
		}
	}

	return ingress
}

func ensureAssociateFIPWithInstance(openstackClientFactory openstackclient.Factory, instance *servers.Server, floatingIP *floatingips.FloatingIP) (bool, error) {
	fipid, err := findFloatingIDByInstanceID(openstackClientFactory, instance.ID)
	if err != nil {
		return false, err
	}

	if fipid != "" {
		return true, nil
	}

	if floatingIP.Status != "ACTIVE" || instance.Status != "ACTIVE" {
		return false, fmt.Errorf("instance or public ip address not ready yet")
	}

	associateOpts := computefip.AssociateOpts{
		FloatingIP: floatingIP.FloatingIP,
	}

	err = associateFIPWithInstance(openstackClientFactory, instance.ID, associateOpts)
	if err != nil {
		return false, fmt.Errorf("failed to associate public ip address %s to instance %s: %w", floatingIP.FloatingIP, instance.Name, err)
	}
	return true, nil
}

func ensureSecurityGroupRules(openstackClientFactory openstackclient.Factory, opt *Options, secGroupID string) error {
	shootsecuritygroup, err := getSecurityGroupId(openstackClientFactory, opt.ShootName)
	if err != nil || shootsecuritygroup == nil {
		return err
	}

	rules := []rules.CreateOpts{IngressAllowSSH(opt, secGroupID), EgressAllowSSHToWorker(opt, secGroupID, shootsecuritygroup[0].ID)}
	for _, item := range rules {
		if err := createSecurityGroupRuleIfNotExist(openstackClientFactory, item); err != nil {
			return err
		}
	}
	return nil
}

func createSecurityGroupRuleIfNotExist(openstackClientFactory openstackclient.Factory, createOpts rules.CreateOpts) error {
	if _, err := createRules(openstackClientFactory, createOpts); err != nil {
		if _, ok := err.(gophercloud.ErrDefault409); ok {
			return nil
		}
		return fmt.Errorf("failed to create Security Group rule %s: %w", createOpts.Description, err)
	}
	logger.Info("Security Group Rule created", "security group rule", createOpts.Description)
	return nil
}

func ensureSecurityGroup(openstackClientFactory openstackclient.Factory, opt *Options) (groups.SecGroup, error) {
	securityGroups, err := getSecurityGroupId(openstackClientFactory, opt.SecurityGroup)
	if err != nil {
		return groups.SecGroup{}, err
	}

	if securityGroups != nil {
		return securityGroups[0], nil
	}

	result, err := createSecurityGroup(openstackClientFactory, groups.CreateOpts{
		Name:        opt.SecurityGroup,
		Description: opt.SecurityGroup,
	})
	if err != nil {
		return groups.SecGroup{}, err
	}

	logger.Info("Security Group created", "security group", result.Name)
	return *result, nil
}
