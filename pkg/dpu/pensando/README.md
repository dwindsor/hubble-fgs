#Serviceabilty: Unifying all DPU commands into FWACTL


The folders in hs-nep/pkg/agent/pensando/ track the generated Go files in hs-dpu-pensando/ssdk/src/github.com/pensando/sw/nic/rudra/.

The AMD SSDK provides two sets of CLIs, pdsctl and dpctl for debugging. The pdsctl cli interacts with the pds_core_app. This is maintained by AMD. The dpctl
cli interacts with the pds_dp_app(hs-dp-app). This has parts of hypershield functionlity woven into it.

The idea with this serviceability exercise is to provide a single CLI, in this case fwactl, for debugging. The fwactl will encompass the hypershield debugs 
and the necessary pdsctl and dpctl commands.

In order to access the dpctl cli options, we need to call the APIs that require the go modules. Importing these modules directly was an issue due to the
large size of hs-dpu-pensando/ repo. To overcome this, we have created a directory hs-nep/pkg/agent/pensando/ and copied over the generated Go files into hs-nep to allow
for easy import. Though these files will remain mostly static, we will include the commands in automation testing to ensure we can catch any failures if there
are any updates from AMD to these files in a new SSDK.

Current mapping is listed below for clarity:

github.com/pensando/sw/nic/rudra/src/dpctl/cli/utils/ —> hs-nep/pkg/agent/pensando/dpctl/cli/utils
github.com/pensando/sw/nic/rudra/build/hs-dp-app/gen/go/dp —> hs-nep/pkg/agent/pensando/hs-dp-app/dp
github.com/pensando/sw/nic/rudra/build/gen/go/pds/ —> hs-nep/pkg/agent/pensando/pds/
github.com/pensando/sw/nic/rudra/build/gen/go/dp/ —> hs-nep/pkg/agent/pensando/dp/
github.com/pensando/sw/nic/rudra/src/dpctl/cli/cmd/ —> hs-nep/pkg/agent/pensando/dpctl/cli/cmd/
github.com/pensando/sw/nic/rudra/build/gen/go/meta/pds —> hs-nep/pkg/agent/pensando/meta/pds 

