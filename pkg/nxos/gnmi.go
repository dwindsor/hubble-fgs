package nxos

import (
	"context"
	"path/filepath"
	"time"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"
	model "github.com/isovalent/hubble-fgs/pkg/nxosmodel"
	"github.com/isovalent/hubble-fgs/pkg/shutdown"

	"github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/gnmic/pkg/api"
	"github.com/openconfig/ygot/ytypes"
	"google.golang.org/protobuf/encoding/prototext"
)

func (n *Nxos) gnmiSubscribe(ctx context.Context, name string, paths []string) {
	logger.GetLogger().Debug("Subcribe: name %s, paths %v", name, paths)
	defer n.Target.StopSubscription(name)

	opts := []api.GNMIOption{api.SubscriptionListMode("stream")}
	for _, path := range paths {
		opts = append(opts, api.Subscription(
			api.Path(path),
			api.SubscriptionMode("on_change")))
	}
	req, err := api.NewSubscribeRequest(opts...)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return
	}
	go n.Target.Subscribe(ctx, req, name)
	rspChan, errChan := n.Target.ReadSubscriptions()

	for {
		select {
		case rsp := <-rspChan:
			n.Lock()
			// l.Debug().Msg(prototext.Format(rsp.Response))
			err := n.procRsp(ctx, rsp.Response)
			if err != nil {
				logger.GetLogger().Error("", logfields.Error, err)
			}
			n.Unlock()

		case tgErr := <-errChan:
			logger.GetLogger().Debug("Subscription stopped, restarting",
				"subscription", tgErr.SubscriptionName, "error", tgErr.Err.Error())
			shutdown.TriggerShutdown(shutdown.RestartExitCode)
			return

		case <-ctx.Done():
			logger.GetLogger().Debug("GNMI subscription context canceled, exiting", "name", name)
			return
		}
	}
}

// Unusued function at the moment.
//func (n *Nxos) gnmiUnsubscribe(_ context.Context, name string) {
//	logger.GetLogger().Debug("gnmiUnsubscribe", "name", name)
//	n.Target.StopSubscription(name)
//}

func (n *Nxos) procRsp(ctx context.Context, rsp *gnmi.SubscribeResponse) error {

	n.LastNotif = time.Now().Unix()
	var err error
	notif := rsp.GetUpdate()
	for _, updt := range notif.GetUpdate() {
		// logger.GetLogger().Debug("update: %+v", updt)
		err = n.procUpdate(ctx, updt)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}
	for _, del := range notif.GetDelete() {
		logger.GetLogger().Debug("delete", "del", del)
		err = n.procDelete(ctx, del)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}
	return err
}

func (n *Nxos) procUpdate(ctx context.Context, updt *gnmi.Update) error {

	// logger.GetLogger().Debug("update: %+v", *updt)
	val := updt.GetVal()
	// logger.GetLogger().Debug("val: %v", val)
	jsonVal := val.GetJsonVal()
	if len(string(jsonVal)) == 0 {
		logger.GetLogger().Debug("Empty keepalive notification received")
		return nil
	}
	logger.GetLogger().Debug("Update jsonVal", "json", string(jsonVal))

	sys := &model.Cisco_NX_OSDevice_System{}
	opts := []ytypes.UnmarshalOpt{&ytypes.IgnoreExtraFields{}}
	err := model.Unmarshal(jsonVal, sys, opts...)
	if err != nil {
		logger.GetLogger().Error("Fail to unmarshal", logfields.Error, err)
		return err
	}

	if sys.InstItems != nil {
		err = n.updtInst(ctx, sys.InstItems)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}
	if sys.SasItems != nil {
		err = n.updtSas(ctx, sys.SasItems)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}
	if sys.SwpkgsItems != nil {
		err = n.updtSwpkgs(ctx, sys.SwpkgsItems)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}
	if sys.BdItems != nil {
		err = n.updtBd(ctx, sys.BdItems)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}

	return nil
}

func (n *Nxos) procDelete(ctx context.Context, del *gnmi.Path) error {
	var err error
	path := "/"

	var elem *gnmi.PathElem
	for _, e := range del.GetElem() {
		// logger.GetLogger().Debug("elem: %+v", e)
		path = filepath.Join(path, e.Name)
		elem = e
	}
	logger.GetLogger().Debug("delete path", "path", path)
	logger.GetLogger().Debug("delete elem", "elem", elem)

	switch path {
	case "/System/inst-items/Inst-list/dom-items/Dom-list":
		key := elem.GetKey()
		name := key["name"]
		err = n.delVbGlobal(ctx, false, name)
		if err != nil {
			logger.GetLogger().Error("failed to delete global vrf", logfields.Error, err)
			return err
		}

	case "/System/bd-items/bd-items/BD-list":
		key := elem.GetKey()
		name := key["fabEncap"]
		err = n.delVbGlobal(ctx, true, name)
		if err != nil {
			logger.GetLogger().Error("failed to delete global vlan", logfields.Error, err)
			return err
		}

	case "/System/sas-items/svc-items/svcinst-items/SvcInstance-list/fwpolicy-items/ipvrf-items/dom-items/Dom-list":
		key := elem.GetKey()
		name := key["name"]
		err = n.delVbService(ctx, false, name)
		if err != nil {
			logger.GetLogger().Error("failed to delete service vrf", logfields.Error, err)
			return err
		}

	case "/System/sas-items/svc-items/svcinst-items/SvcInstance-list/fwpolicy-items/bd-items/vlan-items/Vlan-list":
		key := elem.GetKey()
		name := key["vlanId"]
		err = n.delVbService(ctx, true, name)
		if err != nil {
			logger.GetLogger().Error("failed to delete service vlan", logfields.Error, err)
			return err
		}

	case "/System/sas-items/svc-items/svcinst-items/SvcInstance-list":
		n.delSvcInstance(ctx, elem)

	case "/System/sas-items/svc-items/svcinst-items/SvcInstance-list/fwpolicy-items":
		n.delSvcFw(ctx)

	case "/System/sas-items/svc-items/svcinst-items/SvcInstance-list/ha-items/peer-items/HaPeer-list":
		key := elem.GetKey()
		peer := key["ipAddr"]
		n.delPeer(ctx, peer)

	case "/System/sas-items/svc-items/svcinst-items/SvcInstance-list/ha-items":
		n.delHa(ctx)

	default:
		logger.GetLogger().Debug("Ignore delete", "path", path)
	}
	return nil
}

func (n *Nxos) gnmiSet(ctx context.Context, path string, jstr string) error {
	logger.GetLogger().Debug("gnmiSet path %s, jstr %s", path, jstr)

	req, err := api.NewSetRequest(
		api.Update(
			api.Path(path),
			api.Value(jstr, "json")),
	)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}

	_, err = n.Target.Set(ctx, req)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}
	//l.Debug().Msg(prototext.Format(rsp))
	return nil
}

func (n *Nxos) gnmiDel(ctx context.Context, path string) error {
	if n.Target == nil {
		return nil
	}

	logger.GetLogger().Debug("gnmi delete path", "path", path)
	req, err := api.NewSetRequest(api.Delete(path))
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}

	rsp, err := n.Target.Set(ctx, req)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}
	logger.GetLogger().Debug(prototext.Format(rsp))
	return nil
}

func (n *Nxos) gnmiGet(ctx context.Context, path string) ([]string, error) {
	var jstrs []string

	req, err := api.NewGetRequest(
		api.Path(path),
		api.Encoding("json"),
	)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return jstrs, err
	}
	rsp, err := n.Target.Get(ctx, req)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return jstrs, err
	}
	logger.GetLogger().Debug(prototext.Format(rsp))

	for _, notif := range rsp.Notification {
		for _, update := range notif.GetUpdate() {
			val := update.GetVal()
			// logger.GetLogger().Debug("val: %v", val)
			jsonVal := val.GetJsonVal()
			jstrs = append(jstrs, string(jsonVal))
		}
	}
	return jstrs, nil
}

func (n *Nxos) GnmiClose(_ context.Context) {
	logger.GetLogger().Debug("Closing GNMI client")

	if n.Target != nil {
		err := n.Target.Close()
		if err != nil {
			logger.GetLogger().Error("Fail to close GNMI client", logfields.Error, err)
		}
	}
}
