// SPDX-License-Identifier: Apache-2.0

package complytime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hashicorp/go-hclog"
	"github.com/oscal-compass/compliance-to-policy-go/v2/framework"
	"github.com/oscal-compass/compliance-to-policy-go/v2/framework/actions"
	"github.com/oscal-compass/compliance-to-policy-go/v2/plugin"
	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"
)

// PluginOptions defines global options all complytime plugins should
// support.
type PluginOptions struct {
	// Workspace is the location where all
	// plugin outputs should be written.
	Workspace string `config:"workspace"`
	// Profile is the compliance profile that the plugin should use for
	// pre-defined policy groups.
	Profile string `config:"profile"`
	// UserConfigRoot is the root directory where users customize
	// plugin configuration options
	UserConfigRoot string `config:"userconfigroot"`
}

// NewPluginOptions created a new PluginOptions struct.
func NewPluginOptions() PluginOptions {
	return PluginOptions{}
}

// Validate ensure the required plugin options are set.
func (p PluginOptions) Validate() error {
	// TODO[jpower432]: If these options grow, using third party
	// validation through struct tags could be simpler if the validation
	// logic gets more complex.
	if p.Workspace == "" {
		return errors.New("workspace must be set")
	}
	if p.Profile == "" {
		return errors.New("profile must be set")
	}
	if p.UserConfigRoot != "" {
		if _, err := os.Stat(p.UserConfigRoot); os.IsNotExist(err) {
			return errors.New("user config root does not exist")
		}
	}
	return nil
}

// ToMap transforms the PluginOption struct into a map that can be consumed
// by the C2P Plugin Manager.
func (p PluginOptions) ToMap(pluginId string, logger hclog.Logger) (map[string]string, error) {
	selections := make(map[string]string)
	selections["workspace"] = p.Workspace
	selections["profile"] = p.Profile

	if p.UserConfigRoot != "" {
		configPath := filepath.Join(p.UserConfigRoot, "c2p-"+pluginId+"-manifest.json")
		configFile, err := os.Open(configPath)
		if err != nil {
			if os.IsNotExist(err) {
				logger.Debug(fmt.Sprintf("Plugin manifest file does not exist: %s", configPath))
				return selections, nil
			}
			return selections, fmt.Errorf("failed to open plugin config file: %w", err)
		}
		defer configFile.Close()

		jsonParser := json.NewDecoder(configFile)
		var configManifest plugin.Manifest
		err = jsonParser.Decode(&configManifest)
		if err != nil {
			return selections, fmt.Errorf("failed to parse plugin config file: %w", err)
		}
		for _, configOption := range configManifest.Configuration {
			if configOption.Name == "workspace" || configOption.Name == "profile" {
				continue
			} else {
				if configOption.Default == nil {
					if configOption.Required {
						return selections, fmt.Errorf("missing default value for required option %s in %s", configOption.Name, configPath)
					} else {
						logger.Warn(fmt.Sprintf("Missing default value for %s in %s, it will be set to an empty string", configOption.Name, configPath))
						selections[configOption.Name] = ""
						continue
					}
				}
				selections[configOption.Name] = *configOption.Default
			}

		}
	}
	return selections, nil
}

// Plugins launches and configures plugins with the given complytime global options. This function returns the plugin map with the
// launched plugins, a plugin cleanup function, and an error. The cleanup function should be used if it is not nil.
func Plugins(manager *framework.PluginManager, inputs *actions.InputContext, selections PluginOptions, logger hclog.Logger) (map[plugin.ID]policy.Provider, func(), error) {
	manifests, err := manager.FindRequestedPlugins(inputs.RequestedProviders())
	if err != nil {
		return nil, nil, err
	}

	if selections.UserConfigRoot == "" {
		if _, err := os.Stat(DefaultPluginConfigDir); err == nil {
			selections.UserConfigRoot = DefaultPluginConfigDir
		}
	}
	if err := selections.Validate(); err != nil {
		return nil, nil, fmt.Errorf("failed plugin config validation: %w", err)
	}

	pluginSelectionsMap := make(map[plugin.ID]map[string]string)
	for pluginId := range manifests {
		selectionsMap, err := selections.ToMap(pluginId.String(), logger)
		if err != nil {
			return nil, nil, err
		}
		pluginSelectionsMap[pluginId] = selectionsMap
	}
	getSelections := func(pluginId plugin.ID) map[string]string {
		return pluginSelectionsMap[pluginId]
	}
	plugins, err := manager.LaunchPolicyPlugins(context.Background(), manifests, getSelections)
	// Plugin subprocess has now been launched; cleanup always required below
	if err != nil {
		return nil, manager.Clean, err
	}
	return plugins, manager.Clean, nil
}
