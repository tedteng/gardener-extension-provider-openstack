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
	"errors"
	"fmt"
	"time"

	"github.com/gardener/gardener-extension-provider-openstack/pkg/openstack"
	openstackclient "github.com/gardener/gardener-extension-provider-openstack/pkg/openstack/client"

	"github.com/gardener/gardener/extensions/pkg/controller"
	ctrlerror "github.com/gardener/gardener/extensions/pkg/controller/error"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (a *actuator) Delete(ctx context.Context, bastion *extensionsv1alpha1.Bastion, cluster *controller.Cluster) error {
	logger := a.logger.WithValues("bastion", client.ObjectKeyFromObject(bastion), "operation", "delete")

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
		return fmt.Errorf("could not create openstack client factory: %w", err)
	}

	err = removeBastionInstance(logger, openstackClientFactory, opt)
	if err != nil {
		return fmt.Errorf("failed to remove bastion instance: %w", err)
	}

	err = removePublicIPAddress(logger, openstackClientFactory, opt)
	if err != nil {
		return fmt.Errorf("failed to remove public ip address: %w", err)
	}

	deleted, err := isInstanceDeleted(openstackClientFactory, opt)
	if err != nil {
		return fmt.Errorf("failed to check for bastion instance: %w", err)
	}

	if !deleted {
		return &ctrlerror.RequeueAfterError{
			RequeueAfter: 10 * time.Second,
			Cause:        errors.New("bastion instance is still deleting"),
		}
	}

	err = removeSecurityGroup(openstackClientFactory, opt)
	if err != nil {
		return fmt.Errorf("failed to remove seucirty group: %w", err)
	}
	return nil
}

func removeBastionInstance(logger logr.Logger, openstackClientFactory openstackclient.Factory, opt *Options) error {
	instance, err := getBastionInstance(openstackClientFactory, opt.BastionInstanceName)
	if openstackclient.IgnoreNotFoundError(err) != nil {
		return err
	}

	if instance == nil {
		return nil
	}

	err = deleteBastionInstance(openstackClientFactory, instance[0].ID)

	if err != nil {
		return fmt.Errorf("failed to terminate bastion instance: %w", err)
	}

	logger.Info("Instance removed", "instance", opt.BastionInstanceName)
	return nil
}

func removePublicIPAddress(logger logr.Logger, openstackClientFactory openstackclient.Factory, opt *Options) error {
	fip, err := getFipbyName(openstackClientFactory, opt.BastionInstanceName)
	if err != nil {
		return err
	}

	if fip == nil {
		return nil
	}

	err = deleteFloatingIP(openstackClientFactory, fip[0].ID)
	if err != nil {
		return fmt.Errorf("failed to terminate bastion Public IP: %w", err)
	}

	logger.Info("Public IP removed", "public IP ID", fip[0].ID)
	return nil
}

func removeSecurityGroup(openstackClientFactory openstackclient.Factory, opt *Options) error {
	bastionsecuritygroup, err := getSecurityGroupId(openstackClientFactory, opt.SecurityGroup)
	if err != nil {
		return err
	}

	if bastionsecuritygroup == nil {
		return nil
	}

	return deleteSecurityGroup(openstackClientFactory, bastionsecuritygroup[0].ID)
}

func isInstanceDeleted(openstackClientFactory openstackclient.Factory, opt *Options) (bool, error) {
	instance, err := getBastionInstance(openstackClientFactory, opt.BastionInstanceName)
	if openstackclient.IgnoreNotFoundError(err) != nil {
		return false, err
	}

	return instance == nil, err
}
