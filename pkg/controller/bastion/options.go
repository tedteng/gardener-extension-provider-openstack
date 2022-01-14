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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"

	openstackapi "github.com/gardener/gardener-extension-provider-openstack/pkg/apis/openstack"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/security/rules"

	"github.com/gardener/gardener/extensions/pkg/controller"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

//Maximum length for "base" name due to fact that we use this name to name other openstack resources,
//
const (
	maxLengthForBaseName = 33
	imageRef             = "13850abb-e451-45a2-8437-bdf6de530a19" //m1.tiny
	flavorRef            = "10"
)

// Options contains provider-related information required for setting up
// a bastion instance. This struct combines precomputed values like the
// bastion instance name with the IDs of pre-existing cloud provider
// resources, like the nic name, subnet name etc.
type Options struct {
	BastionInstanceName string
	Region              string
	FlavorRef           string
	ShootName           string
	SecretReference     corev1.SecretReference
	SecurityGroup       string
	SecurityGroupID     string
	UserData            []byte
	ImageRef            string
	FloatingPoolName    string
	CIDRs               []string
	EtherType           rules.RuleEtherType
	EtherIpAddress      string
}

// DetermineOptions determines the required information that are required to reconcile a Bastion on Openstack. This
// function does not create any IaaS resources.
func DetermineOptions(bastion *extensionsv1alpha1.Bastion, cluster *controller.Cluster) (*Options, error) {
	clusterName := cluster.ObjectMeta.Name
	region := cluster.Shoot.Spec.Region

	baseResourceName, err := generateBastionBaseResourceName(clusterName, bastion.Name)
	if err != nil {
		return nil, err
	}

	secretReference := corev1.SecretReference{
		Namespace: cluster.ObjectMeta.Name,
		Name:      v1beta1constants.SecretNameCloudProvider,
	}

	etherType, ip, err := ingressPermissions(bastion)
	if err != nil {
		return nil, errors.New("ingressPermissions error")
	}

	infrastructureConfig := &openstackapi.InfrastructureConfig{}
	err = json.Unmarshal(cluster.Shoot.Spec.Provider.InfrastructureConfig.Raw, infrastructureConfig)
	if err != nil {
		return nil, err
	}

	return &Options{
		ShootName:           clusterName,
		BastionInstanceName: baseResourceName,
		SecretReference:     secretReference,
		SecurityGroup:       securityGroupName(baseResourceName),
		Region:              region,
		FlavorRef:           flavorRef,
		UserData:            []byte(base64.StdEncoding.EncodeToString(bastion.Spec.UserData)),
		ImageRef:            imageRef,
		FloatingPoolName:    infrastructureConfig.FloatingPoolName,
		EtherType:           etherType,
		EtherIpAddress:      ip,
	}, nil
}

func generateBastionBaseResourceName(clusterName string, bastionName string) (string, error) {
	if clusterName == "" {
		return "", fmt.Errorf("clusterName can't be empty")
	}
	if bastionName == "" {
		return "", fmt.Errorf("bastionName can't be empty")
	}

	staticName := clusterName + "-" + bastionName
	h := sha256.New()
	_, err := h.Write([]byte(staticName))
	if err != nil {
		return "", err
	}
	hash := fmt.Sprintf("%x", h.Sum(nil))
	if len([]rune(staticName)) > maxLengthForBaseName {
		staticName = staticName[:maxLengthForBaseName]
	}
	return fmt.Sprintf("%s-bastion-%s", staticName, hash[:5]), nil
}

func ingressPermissions(bastion *extensionsv1alpha1.Bastion) (rules.RuleEtherType, string, error) {
	var etherType rules.RuleEtherType
	var ipAddress string
	for _, ingress := range bastion.Spec.Ingress {
		cidr := ingress.IPBlock.CIDR
		ip, _, err := net.ParseCIDR(cidr)
		if err != nil {
			return "", "", fmt.Errorf("invalid ingress CIDR %q: %w", cidr, err)
		}

		if ip.To4() != nil {
			etherType = rules.EtherType4
			ipAddress = "0.0.0.0/0"
		} else if ip.To16() != nil {
			etherType = rules.EtherType6
			ipAddress = "::/0"
		}
	}
	return etherType, ipAddress, nil
}

// securityGroupName is Security Group resource name
func securityGroupName(baseName string) string {
	return fmt.Sprintf("%s-sg", baseName)
}

// ingressAllowSSHResourceName is Firewall ingress allow SSH rule resource name
func ingressAllowSSHResourceName(baseName string) string {
	return fmt.Sprintf("%s-allow-ssh", baseName)
}

// egressAllowOnlyResourceName is Firewall egress allow only worker node rule resource name
func egressAllowOnlyResourceName(baseName string) string {
	return fmt.Sprintf("%s-egress-worker", baseName)
}
