#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""
@author: superwongo
@project: k8s-certs-generator
@file: k8s-certs-generator
@time: 2021/12/16
"""

import logging
import subprocess
import base64
import shutil
from pathlib import Path
from configparser import ConfigParser


class MyConfigParser(ConfigParser):
    def optionxform(self, optionstr):
        return optionstr


class CertsGenerator(object):
    def __init__(
            self,
            certs_expire=3650,
            k8s_root_dir='/etc/kubernetes',
            service_subnet='10.96.0.0/12',
            log_level='info',
            **kwargs
    ):
        """
        证书生成器
        :param certs_expire: 证书有效期
        :param k8s_root_dir: 证书根目录
        :param logger_level: 日志登记
        :param kwargs: 扩展字段，主要包括证书的专有信息：
            country: C, 国家
            state: ST, 省份
            city: L, 城市
            organization: O, 组织
            organization_unit: OU, 单位
            common_name: CN, 常用名
        """
        self.certs_expire = certs_expire
        self.k8s_root_dir = k8s_root_dir
        self.service_subnet = service_subnet
        self.kwargs = self._init_kwargs(kwargs)
        self._dns_list = []
        self._ipaddr_list = []
        self._advertise_external_ipaddr = None
        self._advertise_internal_ipaddr = None
        self.logger = self.get_logger(log_level)

    @staticmethod
    def _init_kwargs(kwargs):
        kwargs['country'] = kwargs.get('country', 'CN')
        kwargs['state'] = kwargs.get('state', 'shandong')
        kwargs['city'] = kwargs.get('city', 'jinan')
        kwargs['organization'] = kwargs.get('organization', 'personal')
        kwargs['organization_unit'] = kwargs.get('organization_unit', 'personal')
        kwargs['common_name'] = kwargs.get('common_name', 'local.com')
        return kwargs

    @staticmethod
    def get_logger(level='info'):
        """日志模块"""
        logger = logging.getLogger()
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter('[%(asctime)s] %(levelname)s %(process)d %(module)s %(lineno)s: | %(message)s'))
        logger.addHandler(handler)
        logger.setLevel(getattr(logging, level.upper()))
        return logger

    @property
    def certs_root_dir(self):
        """正式根目录，k8s一般为/etc/kubernetes/pki"""
        path = '{}/pki'.format(self.k8s_root_dir)
        self._check_path(path)
        return path

    @property
    def certs_etcd_dir(self):
        """ETCD目录，k8s一般为/etc/kubernetes/pki/etcd"""
        path = '{}/etcd'.format(self.certs_root_dir)
        self._check_path(path)
        return path

    @property
    def certs_ssl_root_dir(self):
        """SSL文件存放目录，临时木库"""
        path = '{}/ssl'.format(self.k8s_root_dir)
        self._check_path(path)
        return path

    @property
    def certs_ssl_etcd_dir(self):
        """SSL文件存放目录，临时木库"""
        path = '{}/ssl/etcd'.format(self.k8s_root_dir)
        self._check_path(path)
        return path

    def register_master(self, ipaddr, hostname):
        """
        注册master节点
        :param ipaddr: master节点IP地址
        :param hostname: master节点主机名
        :return:
        """
        # 默认对外服务的内网IP地址为第一个注册的master节点IP
        if not self._ipaddr_list:
            self._advertise_internal_ipaddr = ipaddr
        if ipaddr not in self._ipaddr_list:
            self._ipaddr_list.append(ipaddr)
        if hostname not in self._dns_list:
            self._dns_list.append(hostname)

    def advertise_external_ipaddr(self, ipaddr):
        """
        对外开放的ApiServer的外网IP
        :param ipaddr: 外网IP地址
        :return:
        """
        self._advertise_external_ipaddr = ipaddr

    def advertise_internal_ipaddr(self, ipaddr):
        """
        对外开放的ApiServer的内网IP
        :param ipaddr: 内网IP地址
        :return:
        """
        self._advertise_internal_ipaddr = ipaddr

    @staticmethod
    def _check_path(path):
        """
        检查路径，自动创建目录
        :param path:
        :return:
        """
        path = Path(path)
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
        elif not path.is_dir():
            raise TypeError('path must be a directory')

    def generator_ca(self, path, name='ca', subject=None, show=False):
        """
        CA证书生成器
        :param path: 证书路径
        :param name: 证书名称
        :param subject: 主题
        :param show: 是否展示证书信息
        :return:
        """
        self.logger.debug('开始创建CA证书：{}/{} subject：{}'.format(path, name, subject))
        key_cmd = 'openssl genrsa -out {ca_path}/{ca_name}.key 2048'.format(
            ca_path=path, ca_name=name
        )
        subprocess.run(key_cmd, shell=True, capture_output=True, check=True)
        ca_cmd = 'openssl req -x509 -new -nodes -key {ca_path}/{ca_name}.key ' \
                 '-days {ca_expire} -out {ca_path}/{ca_name}.crt'
        if subject:
            ca_cmd += ' -subj "{ca_subject}"'
        ca_cmd = ca_cmd.format(ca_path=path, ca_name=name, ca_expire=self.certs_expire, ca_subject=subject)
        subprocess.run(ca_cmd, shell=True, capture_output=True, check=True)
        self.logger.debug('已完成CA证书创建：{}/{} subject：{}'.format(path, name, subject))
        if show:
            self.show_certs(path, name)

    def generator_sa(self, path, name='sa'):
        """
        Service Account生成器
        :param path: 路径
        :param name: 名称
        :return:
        """
        self.logger.debug('开始创建service account公私钥：{}/{}'.format(path, name))
        key_cmd = 'openssl ecparam -name secp521r1 -genkey -noout -out {sa_path}/{sa_name}.key'.format(
            sa_path=path, sa_name=name
        )
        subprocess.run(key_cmd, shell=True, capture_output=True, check=True)
        sa_command = 'openssl ec -in {sa_path}/{sa_name}.key -outform PEM -pubout -out {sa_path}/{sa_name}.pub'.format(
            sa_path=path, sa_name=name
        )
        subprocess.run(sa_command, shell=True, capture_output=True, check=True)
        self.logger.debug('已完成service account公私钥创建：{}/{}'.format(path, name))

    def generate_ca_all(self, show=False):
        """生成所有CA证书
            K8S证书:
                路径: /etc/kubernetes/pki/ca.{crt,key}
                Subject: /CN=kubernetes-ca
            ETCD证书:
                路径: /etc/kubernetes/pki/etcd/ca.{crt,key}
                Subject: /CN=etcd-ca
            前端代理证书:
                路径: /etc/kubernetes/pki/front-proxy-ca.{crt,key}
                Subject: /CN=kubernetes-front-proxy-ca
        """
        self.logger.info('=====开始创建k8s通用CA证书=====')
        self.generator_ca(self.certs_root_dir, 'ca', subject='/CN=kubernetes-ca', show=show)
        self.logger.info('=====已创建k8s通用CA证书=====')
        self.logger.info('=====开始创建etcd CA证书=====')
        self.generator_ca(self.certs_etcd_dir, 'ca', subject='/CN=etcd-ca', show=show)
        self.logger.info('=====已创建etcd CA证书=====')
        self.logger.info('=====开始创建前端代理通用CA证书=====')
        self.generator_ca(self.certs_root_dir, 'front-proxy-ca', subject='/CN=kubernetes-front-proxy-ca', show=show)
        self.logger.info('=====已创建前端代理通用CA证书=====')

    def generate_sa_all(self):
        """生成SA
            /etc/kubernetes/pki/{sa.crt,sa.pub}
        """
        self.logger.info('=====开始创建SA公私钥=====')
        self.generator_sa(self.certs_root_dir)
        self.logger.info('=====已创建SA公私钥=====')

    def generator_csr_conf(self, path, name, common_name=None, organization=None, kind=None, alt_names=None):
        """
        证书请求文件csr配置文件生成器
        :param path: 路径
        :param name: 名称
        :param common_name: 常用名
        :param organization: 组织
        :param kind: 类型：server, client
        :param alt_names: 备选名称
        :return:
        """
        self.logger.debug('开始组织创建csr的配置文件内容：{}/{}'.format(path, name))
        csr_conf = MyConfigParser()
        # ---------- req section ---------- #
        csr_conf.add_section('req')
        csr_conf.set('req', 'default_bits', '2048')
        csr_conf.set('req', 'prompt', 'no')
        csr_conf.set('req', 'default_md', 'sha256')
        csr_conf.set('req', 'req_extensions', 'req_ext')
        csr_conf.set('req', 'distinguished_name', 'req_distinguished_name')

        # ---------- dn section ---------- #
        csr_conf.add_section('req_distinguished_name')
        for key, value in {
            'C': 'country',
            'ST': 'state',
            'L': 'city',
            'O': 'organization',
            'OU': 'organization_unit',
            'CN': 'common_name',
        }.items():
            if value in self.kwargs:
                if key == 'CN' and common_name:
                    csr_conf.set('req_distinguished_name', key, common_name)
                elif key == 'O' and organization:
                    csr_conf.set('req_distinguished_name', key, organization)
                else:
                    csr_conf.set('req_distinguished_name', key, self.kwargs[value])

        # ---------- v3_ext section ---------- #
        csr_conf.add_section('v3_ext')
        csr_conf.set('v3_ext', 'authorityKeyIdentifier', 'keyid,issuer:always')
        csr_conf.set('v3_ext', 'basicConstraints', 'CA:FALSE')
        csr_conf.set('v3_ext', 'keyUsage', 'keyEncipherment,dataEncipherment')
        if kind == 'server':
            csr_conf.set('v3_ext', 'extendedKeyUsage', 'serverAuth')
        elif kind == 'client':
            csr_conf.set('v3_ext', 'extendedKeyUsage', 'clientAuth')
        else:
            csr_conf.set('v3_ext', 'extendedKeyUsage', 'serverAuth,clientAuth')

        # ---------- alt_names section ---------- #
        if alt_names:
            csr_conf.add_section('alt_names')
            for item in alt_names:
                csr_conf.set('alt_names', item[0], item[1])

        # ---------- req_ext section ---------- #
        csr_conf.add_section('req_ext')
        if csr_conf.has_section('alt_names'):
            # ---------- v3_ext section ---------- #
            csr_conf.set('v3_ext', 'subjectAltName', '@alt_names')
            # ---------- req_ext section ---------- #
            csr_conf.set('req_ext', 'subjectAltName', '@alt_names')

        self.logger.debug('已组织创建csr的配置文件内容，开始生成配置文件：{}/{}'.format(path, name))
        with open('{csr_path}/{csr_name}.conf'.format(csr_path=path, csr_name=name), 'w') as f:
            csr_conf.write(f)
        self.logger.debug('已完成csr的配置文件创建：{}/{}'.format(path, name))

    def generator_certs(self, path, name, ca_path, ca_name, ssl_path, show=False):
        """
        证书生成器
        :param path: 路径
        :param name: 名称
        :param ca_path: CA根证书路径
        :param ca_name: CA根证书Key路径
        :param ssl_path: SSL文件路径 (csr、conf)
        :param show: 是否展示证书内容
        :return:
        """
        self.logger.debug('开始创建证书：{}/{}, ca: {}/{}'.format(path, name, ca_path, ca_name))
        key_cmd = 'openssl genrsa -out {path}/{name}.key 2048'.format(path=path, name=name)
        subprocess.run(key_cmd, shell=True, capture_output=True, check=True)
        csr_cmd = 'openssl req -new -key {path}/{name}.key -out {ssl_path}/{name}.csr -config {ssl_path}/{name}.conf'\
            .format(path=path, name=name, ssl_path=ssl_path)
        subprocess.run(csr_cmd, shell=True, capture_output=True, check=True)
        crt_cmd = 'openssl x509 -req -in {ssl_path}/{name}.csr -CA {ca_path}/{ca_name}.crt ' \
                  '-CAkey {ca_path}/{ca_name}.key -CAcreateserial -out {path}/{name}.crt -days {ca_expire} ' \
                  '-extensions v3_ext -extfile {ssl_path}/{name}.conf'.format(
            path=path, name=name, ca_path=ca_path, ca_name=ca_name, ssl_path=ssl_path, ca_expire=self.certs_expire
        )
        subprocess.run(crt_cmd, shell=True, capture_output=True, check=True)
        self.logger.debug('已完成证书创建：{}/{}, ca: {}/{}'.format(path, name, ca_path, ca_name))
        if show:
            self.show_certs(path, name)

    def generate_certs_etcd(self, show=False):
        """生成ETCD证书
            默认CN: kube-etcd
            父级CA: etcd-ca
            类型 (Kind): server, client
            主机 (SAN): localhost, 127.0.0.1
            文件: /etc/kubernetes/pki/etcd/server.{crt,key}
                 /etc/kubernetes/pki/ssl/etcd/server.{conf,csr}
        """
        alt_names = []
        dns_list = ['localhost']
        dns_list.extend(self._dns_list)
        ipaddr_list = ['127.0.0.1', '::1']
        ipaddr_list.extend(self._ipaddr_list)
        for index, dns in enumerate(dns_list):
            alt_names.append(('DNS.{}'.format(index), dns))
        for index, ipaddr in enumerate(ipaddr_list):
            alt_names.append(('IP.{}'.format(index), ipaddr))
        self.logger.info('=====开始创建etcd服务端证书csr配置文件=====')
        self.generator_csr_conf(self.certs_ssl_etcd_dir, 'server', common_name='kube-etcd', alt_names=alt_names)
        self.logger.info('=====已创建etcd服务端证书csr配置文件=====')
        self.logger.info('=====开始创建etcd服务端证书=====')
        self.generator_certs(
            self.certs_etcd_dir,
            'server',
            self.certs_etcd_dir,
            'ca',
            self.certs_ssl_etcd_dir,
            show=show,
        )
        self.logger.info('=====已创建etcd服务端证书=====')

    def generate_certs_etcd_peer(self, show=False):
        """生成ETCD peer证书
            默认CN: kube-etcd-peer
            父级CA: etcd-ca
            类型 (Kind): server, client
            主机 (SAN): <hostname>, <Host_IP>, localhost, 127.0.0.1
            文件: /etc/kubernetes/pki/etcd/peer.{crt,key}
                 /etc/kubernetes/pki/ssl/etcd/peer.{conf,csr}
        """
        alt_names = []
        dns_list = ['localhost']
        dns_list.extend(self._dns_list)
        ipaddr_list = ['127.0.0.1', '::1']
        ipaddr_list.extend(self._ipaddr_list)
        for index, dns in enumerate(dns_list):
            alt_names.append(('DNS.{}'.format(index), dns))
        for index, ipaddr in enumerate(ipaddr_list):
            alt_names.append(('IP.{}'.format(index), ipaddr))
        self.logger.info('=====开始创建etcd peer证书csr配置文件=====')
        self.generator_csr_conf(self.certs_ssl_etcd_dir, 'peer', common_name='kube-etcd-peer', alt_names=alt_names)
        self.logger.info('=====已创建etcd peer证书csr配置文件=====')
        self.logger.info('=====开始创建etcd peer证书=====')
        self.generator_certs(
            self.certs_etcd_dir,
            'peer',
            self.certs_etcd_dir,
            'ca',
            self.certs_ssl_etcd_dir,
            show=show,
        )
        self.logger.info('=====已创建etcd peer证书=====')

    def generate_certs_etcd_healthcheck(self, show=False):
        """生成ETCD健康检查客户端证书
            默认CN: kube-etcd-healthcheck-client
            父级CA: etcd-ca
            类型 (Kind): client
            文件: /etc/kubernetes/pki/etcd/healthcheck-client.{crt,key}
                 /etc/kubernetes/pki/ssl/etcd/healthcheck-client.{conf,csr}
        """
        self.logger.info('=====开始创建etcd healthcheck客户端证书csr配置文件=====')
        self.generator_csr_conf(
            self.certs_ssl_etcd_dir,
            'healthcheck-client',
            common_name='kube-etcd-healthcheck-client',
            kind='client'
        )
        self.logger.info('=====已创建etcd healthcheck客户端证书csr配置文件=====')
        self.logger.info('=====开始创建etcd healthcheck客户端证书=====')
        self.generator_certs(
            self.certs_etcd_dir,
            'healthcheck-client',
            self.certs_etcd_dir,
            'ca',
            self.certs_ssl_etcd_dir,
            show=show,
        )
        self.logger.info('=====已创建etcd healthcheck客户端证书=====')

    def generate_certs_apiserver_etcd(self, show=False):
        """生成APIServer访问ETCD客户端证书
            默认CN: kube-apiserver-etcd-client
            父级CA: etcd-ca
            O (位于 Subject 中): system:masters
            类型 (Kind): client
            文件: /etc/kubernetes/pki/apiserver-etcd-client.{crt,key}
                 /etc/kubernetes/pki/ssl/apiserver-etcd-client.{conf,csr}
        """
        self.logger.info('=====开始创建apiserver访问etcd客户端证书csr配置文件=====')
        self.generator_csr_conf(
            self.certs_ssl_root_dir,
            'apiserver-etcd-client',
            common_name='kube-apiserver-etcd-client',
            organization='system:masters',
            kind='client'
        )
        self.logger.info('=====已创建apiserver访问etcd客户端证书csr配置文件=====')
        self.logger.info('=====开始创建apiserver访问etcd客户端证书=====')
        self.generator_certs(
            self.certs_root_dir,
            'apiserver-etcd-client',
            self.certs_etcd_dir,
            'ca',
            self.certs_ssl_root_dir,
            show=show,
        )
        self.logger.info('=====已创建apiserver访问etcd客户端证书=====')

    def generate_certs_apiserver(self, show=False):
        """生成APIServer服务端证书
            默认CN: kube-apiserver
            父级CA: kubernetes-ca
            类型 (Kind): server,
            主机 (SAN): <hostname>, <Host_IP>, <advertise_IP>,
                        kubernetes
                        kubernetes.default
                        kubernetes.default.svc
                        kubernetes.default.svc.cluster
                        kubernetes.default.svc.cluster.local
            文件: /etc/kubernetes/pki/apiserver.{crt,key}
                  /etc/kubernetes/pki/ssl/apiserver.{conf,csr}
        """
        alt_names = []
        dns_list = ['kubernetes',
                    'kubernetes.default',
                    'kubernetes.default.svc',
                    'kubernetes.default.svc.cluster',
                    'kubernetes.default.svc.cluster.local']
        dns_list.extend(self._dns_list)
        kubernetes_service_ip = '.'.join([self.service_subnet.rsplit('.', 1)[0], '1'])
        ipaddr_list = [kubernetes_service_ip]
        ipaddr_list.extend(self._ipaddr_list)
        if self._advertise_internal_ipaddr:
            ipaddr_list.append(self._advertise_internal_ipaddr)
        if self._advertise_external_ipaddr:
            ipaddr_list.append(self._advertise_external_ipaddr)
        for index, dns in enumerate(dns_list):
            alt_names.append(('DNS.{}'.format(index), dns))
        for index, ipaddr in enumerate(ipaddr_list):
            alt_names.append(('IP.{}'.format(index), ipaddr))
        self.logger.info('=====开始创建apiserver服务端证书csr配置文件=====')
        self.generator_csr_conf(
            self.certs_ssl_root_dir,
            'apiserver',
            common_name='kube-apiserver',
            kind='server',
            alt_names=alt_names
        )
        self.logger.info('=====已创建apiserver服务端证书csr配置文件=====')
        self.logger.info('=====开始创建apiserver服务端证书=====')
        self.generator_certs(
            self.certs_root_dir,
            'apiserver',
            self.certs_root_dir,
            'ca',
            self.certs_ssl_root_dir,
            show=show,
        )
        self.logger.info('=====已创建apiserver服务端证书=====')

    def generate_apiserver_kubelet(self, show=False):
        """生成APIServer访问Kubelet客户端证书
            默认CN: kube-apiserver-kubelet-client
            父级CA: kubernetes-ca
            O (位于 Subject 中): system:masters
            类型 (Kind): client
            文件: /etc/kubernetes/pki/apiserver-kubelet-client.{crt,key}
                 /etc/kubernetes/pki/ssl/apiserver-kubelet-client.{conf,csr}
        """
        self.logger.info('=====开始创建apiserver访问kubelet客户端证书csr配置文件=====')
        self.generator_csr_conf(
            self.certs_ssl_root_dir,
            'apiserver-kubelet-client',
            common_name='kube-apiserver-kubelet-client',
            organization='system:masters',
            kind='client'
        )
        self.logger.info('=====已创建apiserver访问kubelet客户端证书csr配置文件=====')
        self.logger.info('=====开始创建apiserver访问kubelet客户端证书=====')
        self.generator_certs(
            self.certs_root_dir,
            'apiserver-kubelet-client',
            self.certs_root_dir,
            'ca',
            self.certs_ssl_root_dir,
            show=show,
        )
        self.logger.info('=====已创建apiserver访问kubelet客户端证书=====')

    def generate_front_proxy_kubelet(self, show=False):
        """生成前端代理访问Kubelet客户端证书
            默认CN: front-proxy-client
            父级CA: kubernetes-front-proxy-ca
            类型 (Kind): client
            文件: /etc/kubernetes/pki/front-proxy-client.{crt,key}
                 /etc/kubernetes/pki/ssl/front-proxy-client.{conf,csr}
        """
        self.logger.info('=====开始创建前端代理访问kubelet客户端证书csr配置文件=====')
        self.generator_csr_conf(
            self.certs_ssl_root_dir,
            'front-proxy-client',
            common_name='front-proxy-client',
            kind='client'
        )
        self.logger.info('=====已创建前端代理访问kubelet客户端证书csr配置文件=====')
        self.logger.info('=====开始创建前端代理访问kubelet客户端证书=====')
        self.generator_certs(
            self.certs_root_dir,
            'front-proxy-client',
            self.certs_root_dir,
            'front-proxy-ca',
            self.certs_ssl_root_dir,
            show=show,
        )
        self.logger.info('=====已创建前端代理访问kubelet客户端证书=====')

    def generate_certs_all(self, show=False):
        """生成所有证书"""
        self.generate_certs_etcd(show)
        self.generate_certs_etcd_peer(show)
        self.generate_certs_etcd_healthcheck(show)
        self.generate_certs_apiserver_etcd(show)
        self.generate_certs_apiserver(show)
        self.generate_apiserver_kubelet(show)
        self.generate_front_proxy_kubelet(show)

    def generator_cluster_config(self, cert_name, conf_name, common_name):
        """
        集群配置文件生成器
        :param cert_name: admin-apiserver-client.crt | controller-manager-apiserver-client.crt | scheduler-apiserver-client.crt
        :param conf_name: admin.conf | controller-manager.conf | scheduler.conf
        :param common_name: 常用名
        :return:
        """
        template = """apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: {certificate_authority_data}
    server: {api_server}
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: {cn}
  name: {cn}@kubernetes
current-context: {cn}@kubernetes
kind: Config
preferences: {{}}
users:
- name: {cn}
  user:
    client-certificate-data: {client_certificate_data}
    client-key-data: {client_key_data}"""
        self.logger.debug('开始读取ca证书: {}/ca.crt'.format(self.certs_root_dir))
        with open('{}/ca.crt'.format(self.certs_root_dir), 'rb') as f:
            certificate_authority_data = base64.b64encode(f.read())
        self.logger.debug('开始读取cert证书: {}/{}.crt'.format(self.certs_ssl_root_dir, cert_name))
        with open('{}/{}.crt'.format(self.certs_ssl_root_dir, cert_name), 'rb') as f:
            client_certificate_data = base64.b64encode(f.read())
        self.logger.debug('开始读取cert key: {}/{}.key'.format(self.certs_ssl_root_dir, cert_name))
        with open('{}/{}.key'.format(self.certs_ssl_root_dir, cert_name), 'rb') as f:
            client_key_data = base64.b64encode(f.read())
        data = template.format(
            certificate_authority_data=str(certificate_authority_data),
            api_server='https://{}:6443'.format(self._advertise_internal_ipaddr),
            cn=common_name,
            client_certificate_data=str(client_certificate_data),
            client_key_data=str(client_key_data),
        )
        self.logger.debug('开始写入cluster config文件: {}/{}.conf'.format(self.k8s_root_dir, conf_name))
        with open('{}/{}.conf'.format(self.k8s_root_dir, conf_name), 'w') as f:
            f.write(data)
        self.logger.debug('已完成cluster config文件写入: {}/{}.conf'.format(self.k8s_root_dir, conf_name))

    def generate_cluster_config_admin(self, show=False):
        """生成集群配置文件admin.conf
            默认CN: kubernetes-admin
            父级CA: kubernetes-ca
            O (位于 Subject 中): system:masters
            类型 (Kind): client
            文件: /etc/kubernetes/pki/ssl/admin-apiserver-client.{crt,key,conf,csr}
        """
        self.logger.info('=====开始创建admin访问apiserver客户端证书csr配置文件=====')
        self.generator_csr_conf(
            self.certs_ssl_root_dir,
            'admin-apiserver-client',
            common_name='kubernetes-admin',
            organization='system:masters',
            kind='client'
        )
        self.logger.info('=====已创建admin访问apiserver客户端证书csr配置文件=====')
        self.logger.info('=====开始创建admin访问apiserver客户端证书=====')
        self.generator_certs(
            self.certs_ssl_root_dir,
            'admin-apiserver-client',
            self.certs_root_dir,
            'ca',
            self.certs_ssl_root_dir,
            show=show,
        )
        self.logger.info('=====已创建admin访问apiserver客户端证书=====')
        self.logger.info('=====开始创建admin.conf配置文件=====')
        self.generator_cluster_config(
            'admin-apiserver-client',
            'admin',
            'kubernetes-admin'
        )
        self.logger.info('=====已完成admin.conf配置文件创建=====')

    def generate_cluster_config_controller_manager(self, show=False):
        """生成集群配置文件controller-manager.conf
            默认CN: system:kube-controller-manager
            父级CA: kubernetes-ca
            类型 (Kind): client
            文件: /etc/kubernetes/pki/ssl/controller-manager-apiserver-client.{crt,key,conf,csr}
        """
        self.logger.info('=====开始创建controller-manager访问apiserver客户端证书csr配置文件=====')
        self.generator_csr_conf(
            self.certs_ssl_root_dir,
            'controller-manager-apiserver-client',
            common_name='system:kube-controller-manager',
            kind='client'
        )
        self.logger.info('=====已创建controller-manager访问apiserver客户端证书csr配置文件=====')
        self.logger.info('=====开始创建controller-manager访问apiserver客户端证书=====')
        self.generator_certs(
            self.certs_ssl_root_dir,
            'controller-manager-apiserver-client',
            self.certs_root_dir,
            'ca',
            self.certs_ssl_root_dir,
            show=show,
        )
        self.logger.info('=====已创建controller-manager访问apiserver客户端证书=====')
        self.logger.info('=====开始创建controller-manager.conf配置文件=====')
        self.generator_cluster_config(
            'controller-manager-apiserver-client',
            'controller-manager',
            'system:kube-controller-manager'
        )
        self.logger.info('=====已完成controller-manager.conf配置文件创建=====')

    def generate_cluster_config_scheduler(self, show=False):
        """生成集群配置文件scheduler.conf
            默认CN: system:kube-scheduler
            父级CA: kubernetes-ca
            类型 (Kind): client
            文件: /etc/kubernetes/pki/ssl/scheduler-apiserver-client.{crt,key,conf,csr}
        """
        self.logger.info('=====开始创建scheduler访问apiserver客户端证书csr配置文件=====')
        self.generator_csr_conf(
            self.certs_ssl_root_dir,
            'scheduler-apiserver-client',
            common_name='system:kube-scheduler',
            kind='client'
        )
        self.logger.info('=====已创建scheduler访问apiserver客户端证书csr配置文件=====')
        self.logger.info('=====开始创建scheduler访问apiserver客户端证书=====')
        self.generator_certs(
            self.certs_ssl_root_dir,
            'scheduler-apiserver-client',
            self.certs_root_dir,
            'ca',
            self.certs_ssl_root_dir,
            show=show,
        )
        self.logger.info('=====已创建scheduler访问apiserver客户端证书=====')
        self.logger.info('=====开始创建scheduler.conf配置文件=====')
        self.generator_cluster_config(
            'scheduler-apiserver-client',
            'scheduler',
            'system:kube-scheduler'
        )
        self.logger.info('=====已完成scheduler.conf配置文件创建=====')

    def generate_cluster_config_all(self, show=False):
        self.generate_cluster_config_admin(show)
        self.generate_cluster_config_controller_manager(show)
        self.generate_cluster_config_scheduler(show)

    def clear(self):
        shutil.rmtree(self.certs_ssl_root_dir)

    def show_certs(self, path, name):
        show_cmd = 'openssl x509 -in {}/{}.crt -noout -text'.format(path, name)
        ret = subprocess.run(show_cmd, shell=True, capture_output=True, check=True)
        self.logger.info('=====证书[{}/{}.crt]内容如下：====='.format(path, name))
        self.logger.info(ret.stdout.decode())


def main():
    title = """  _  __ ___  ____     ____             _           ____                                 _               
 | |/ /( _ )/ ___|   / ___| ___  _ __ | |_  ___   / ___|  ___  _ __    ___  _ __  __ _ | |_  ___   _ __ 
 | ' / / _ \\___ \  | |    / _ \| '__|| __|/ __| | |  _  / _ \| '_ \  / _ \| '__|/ _` || __|/ _ \ | '__|
 | . \| (_) |___) | | |___|  __/| |   | |_ \__ \ | |_| ||  __/| | | ||  __/| |  | (_| || |_| (_) || |   
 |_|\_\\___/|____/   \____|\___||_|    \__||___/  \____| \___||_| |_| \___||_|   \__,_| \__|\___/ |_|   
                                                                                                        """
    print('\n\n+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+')
    print(title)
    print('+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n')
    print('请依次输入一下内容（使用默认值可以直接回车）：\n')
    try:
        k8s_root_dir = input('> K8S配置文件根目录（/etc/kubernetes）：') or '/etc/kubernetes'
        service_subnet = input('> K8S Service子网CIDR（10.96.0.0/12）：') or '10.96.0.0/12'
        log_level = input('> 命令行打印日志Level（info）：') or 'info'
        certs_expire = input('> 证书有效期（3650）：') or 3640
        country = input('> 证书专用信息-C（CN）：') or 'CN'
        state = input('> 证书专用信息-ST（shandong）：') or 'shandong'
        city = input('> 证书专用信息-L（jinan）：') or 'jinan'
        organization = input('> 证书专用信息-O（personal）：') or 'personal'
        organization_unit = input('> 证书专用信息-OU（personal）：') or 'personal'
        common_name = input('> 证书专用信息-CN（local.com）：') or 'local.com'
        generator = CertsGenerator(
            k8s_root_dir=k8s_root_dir,
            service_subnet=service_subnet,
            log_level=log_level,
            certs_expire=certs_expire,
            country=country,
            state=state,
            city=city,
            organization=organization,
            organization_unit=organization_unit,
            common_name=common_name,
        )
        more_master = 'yes'
        internal_ipaddr = None
        while more_master.lower() in ('yes', 'y'):
            master_ipaddr, master_hostname = None, None
            while not master_ipaddr:
                master_ipaddr = input('> 请输入Master节点IP地址（必填）：')
            while not master_hostname:
                master_hostname = input('> 请输入Master节点Hostname（必填）：')
            generator.register_master(master_ipaddr, master_hostname)
            if not internal_ipaddr:
                internal_ipaddr = master_ipaddr
            more_master = input('> 是否继续添加Master节点（yes/no，默认no）：')
        internal_ipaddr = input('> 请输入Master节点对外服务内网地址（{}）：'.format(internal_ipaddr)) or internal_ipaddr
        generator.advertise_internal_ipaddr(internal_ipaddr)
        external_ipaddr = input('> 请输入Master节点对外服务外网地址（非必填）：')
        if external_ipaddr:
            generator.advertise_external_ipaddr(external_ipaddr)
        is_show = input('> 是否展示生成证书具体信息（yes/no，默认no）：')
        show = True if is_show.lower() in ('yes', 'y') else False
        is_start = input('> 是否开始生成证书（yes/no，默认yes）：') or 'yes'
        if is_start.lower() in ('yes', 'y'):
            print('\n\n')
            generator.generate_ca_all(show=show)
            generator.generate_certs_all(show=show)
            generator.generate_sa_all()
            generator.generate_cluster_config_all(show=show)
            generator.clear()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
