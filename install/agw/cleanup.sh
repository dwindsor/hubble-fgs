#!/bin/bash
# Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Isovalent Inc and its suppliers, if any. The intellectual and technical
# concepts contained herein are proprietary to Isovalent Inc and its suppliers
# and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law.  Dissemination of this information
# or reproduction of this material is strictly forbidden unless prior written
# permission is obtained from Isovalent Inc.

/usr/src/app/gnmic -a $NX_GRPC_IP:$NX_GRPC_PORT -u $NX_GRPC_USER -p $NX_GRPC_PASS --skip-verify --gzip set --delete '/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/fwpolicystate-items'
/usr/src/app/gnmic -a $NX_GRPC_IP:$NX_GRPC_PORT -u $NX_GRPC_USER -p $NX_GRPC_PASS --skip-verify --gzip set --delete '/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/sagent-items/ext-items/systemState'
/usr/src/app/gnmic -a $NX_GRPC_IP:$NX_GRPC_PORT -u $NX_GRPC_USER -p $NX_GRPC_PASS --skip-verify --gzip set --delete '/System/serviceredir-items/inst-items/pmap-items'
/usr/src/app/gnmic -a $NX_GRPC_IP:$NX_GRPC_PORT -u $NX_GRPC_USER -p $NX_GRPC_PASS --skip-verify --gzip set --delete '/System/serviceredir-items/inst-items/service-items'
/usr/src/app/gnmic -a $NX_GRPC_IP:$NX_GRPC_PORT -u $NX_GRPC_USER -p $NX_GRPC_PASS --skip-verify --gzip set --delete '/System/serviceredir-items/inst-items/dom-items'
