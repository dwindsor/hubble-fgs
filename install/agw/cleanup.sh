#!/bin/bash

/usr/src/app/gnmic -a $NX_GRPC_IP:$NX_GRPC_PORT -u $NX_GRPC_USER -p $NX_GRPC_PASS --skip-verify --gzip set --delete '/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicystate-items'
/usr/src/app/gnmic -a $NX_GRPC_IP:$NX_GRPC_PORT -u $NX_GRPC_USER -p $NX_GRPC_PASS --skip-verify --gzip set --delete '/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/sagent-items/ext-items/systemState'
/usr/src/app/gnmic -a $NX_GRPC_IP:$NX_GRPC_PORT -u $NX_GRPC_USER -p $NX_GRPC_PASS --skip-verify --gzip set --delete '/System/serviceredir-items/inst-items/pmap-items'
/usr/src/app/gnmic -a $NX_GRPC_IP:$NX_GRPC_PORT -u $NX_GRPC_USER -p $NX_GRPC_PASS --skip-verify --gzip set --delete '/System/serviceredir-items/inst-items/service-items'
/usr/src/app/gnmic -a $NX_GRPC_IP:$NX_GRPC_PORT -u $NX_GRPC_USER -p $NX_GRPC_PASS --skip-verify --gzip set --delete '/System/serviceredir-items/inst-items/dom-items'
