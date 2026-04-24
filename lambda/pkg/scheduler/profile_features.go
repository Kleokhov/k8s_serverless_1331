package scheduler

import (
	schedulerapi "k8s.io/kubernetes/pkg/scheduler/apis/config"
	"k8s.io/kubernetes/pkg/scheduler/framework"
	"k8s.io/kubernetes/pkg/scheduler/framework/plugins/names"
)

type profileFeatures struct {
	hasPostFilter bool
	hasReserve    bool
	hasPermit     bool
	hasPreBind    bool
	hasPostBind   bool
	bindPlugins   []schedulerapi.Plugin
}

func buildProfileFeatures(fwk framework.Framework) profileFeatures {
	plugins := fwk.ListPlugins()
	return profileFeatures{
		hasPostFilter: len(plugins.PostFilter.Enabled) > 0,
		hasReserve:    len(plugins.Reserve.Enabled) > 0,
		hasPermit:     len(plugins.Permit.Enabled) > 0,
		hasPreBind:    len(plugins.PreBind.Enabled) > 0,
		hasPostBind:   len(plugins.PostBind.Enabled) > 0,
		bindPlugins:   append([]schedulerapi.Plugin(nil), plugins.Bind.Enabled...),
	}
}

func (f profileFeatures) simpleBindingPath() bool {
	return !f.hasReserve &&
		!f.hasPermit &&
		!f.hasPreBind &&
		!f.hasPostBind &&
		len(f.bindPlugins) == 1 &&
		f.bindPlugins[0].Name == names.DefaultBinder
}

func (f profileFeatures) needsPodsToActivate() bool {
	return f.hasPostFilter || f.hasReserve || f.hasPermit || f.hasPreBind || f.hasPostBind
}
