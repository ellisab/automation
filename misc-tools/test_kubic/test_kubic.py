#!/usr/bin/env python

"""
    Runs end-to-end product tests.
    This script can be run from Jenkins or manually, on developer desktops or servers.
"""

from argparse import Namespace
from functools import wraps
import os
import re
import json
import subprocess
import sys

import requests

from timeout_decorator import timeout

__version__ = "0.0.1"

help = """
This script is meant to be run manually on test servers, developer desktops
and by Jenkins.

Warning: it removes docker containers, VMs, images, and network configuration.

It creates a workspace directory and a virtualenv.

Requires root privileges.

"""


# Jenkins env vars: BUILD_NUMBER

env_defaults = dict(
    CHANGE_TARGET="master",
    HOSTNAME="dev-desktop",
    CHOOSE_CRIO="false",
    WORKSPACE=os.path.join(os.getcwd(), "workspace"),
    BMCONF="error-bare-metal-config-file-not-set",
)

# global conf
conf = None

def getvar(name):
    """Resolve in order:
    - CLI k/v variable (case insensitive)
    - environment variable (case sensitive)
    - default value
    """
    lc = name.lower()
    if hasattr(conf, lc):
        return getattr(conf, lc)
    if name in os.environ:
        return os.environ[name]
    if name in env_defaults:
        return env_defaults[name]
    raise Exception("env variable '{}' not found".format(name))


def replace_vars(s):
    """Replace jenkins ${} variables"""
    try:
        for match in re.findall('\$\{[\w\-\.]+\}', s):
            varname = match[2:-1]
            val = getvar(varname)
            s = s.replace(match, val, 1)  # replace only the first
        return s
    except Exception as e:
        print("Error while replacing '{}'".format(s))
        print(e)
        raise


def sh(cmd, env=None):
    """emulate Jenkins `sh`"""
    cmd = replace_vars(cmd)
    path = replace_vars("${WORKSPACE}")
    print("  in {}".format(path))
    print("$ {}".format(cmd))
    if conf.dryrun:
        return

    p = subprocess.call(cmd, cwd=path, stderr=sys.stdout.buffer, shell=True,
                        env=env)
    if p != 0:
        raise Exception("'{}' exited with {}".format(cmd, p))

def sh_fork(cmd):
    """emulate Jenkins `sh`"""
    cmd = replace_vars(cmd)
    print("$ {}".format(cmd))
    if conf.dryrun:
        return
    return subprocess.Popen(cmd, shell=True)

def shp(path, cmd, env=None):
    """emulate Jenkins `sh`"""
    cmd = replace_vars(cmd)
    path = replace_vars(path)
    if not os.path.isabs(path):
        path = os.path.join(replace_vars("${WORKSPACE}"), path)

    print("  in {}".format(path))
    print("$ {}".format(cmd))
    if conf.dryrun:
        return

    subprocess.check_call(cmd, cwd=path, shell=True, env=env)

def create_workspace_dir():
    path = replace_vars("${WORKSPACE}")
    try:
        os.makedirs(path)
    except:
        print(path, "created")
        pass

## nested output blocks

DOT = '\033[34m●\033[0m'
DOT_exit = '\033[32m●\033[0m'

_stepdepth = 0
def step(foo=None):
    def deco(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            global _stepdepth
            _stepdepth += 1
            print("{}  {} {}".format(DOT * _stepdepth, f.__name__,
                                     f.__doc__ or ""))
            r = f(*args, **kwargs)
            print("{}  exiting {}".format(DOT_exit * _stepdepth, f.__name__))
            _stepdepth -= 1
            return r
        return wrapped
    return deco




@timeout(5)
@step()
def info():
    """Node info"""
    print("Env vars: {}".format(sorted(os.environ)))

    sh('ip a')
    sh('ip r')
    sh('cat /etc/resolv.conf')
    #def response = httpRequest(url: 'http://169.254.169.254/latest/meta-data/public-ipv4')
    #echo "Public IPv4: ${response.content}"<Paste>


@timeout(125)
@step()
def initial_cleanup():
    """Cleanup"""
    sh('rm -rf ${WORKSPACE} || : ')
    create_workspace_dir()
    sh('mkdir -p ${WORKSPACE}/logs')
    sh('chmod a+x ${WORKSPACE}')
    if conf.stack_type == 'bare-metal':
        return

    sh('virsh net-undefine caasp-dev-net || : ')
    sh('virsh net-destroy caasp-dev-net || : ')
    sh('virsh net-undefine net || : ')
    sh('virsh net-destroy net || : ')
    sh('for i in $(virsh list --all --name);do echo $i;virsh destroy $i || : ;done')
    sh('for i in $(virsh list --all --name);do echo $i;virsh undefine $i;done')
    sh('for fn in $(virsh vol-list default|awk \'/var/ {print $2}\'); do echo $fn; virsh vol-delete $fn ; done')
    sh('virsh list --all')
    sh('virsh net-list --all')
    sh('virsh pool-list --all')
    sh('virsh vol-list default')
    sh('docker rm -f $(docker ps -a -q) || :')
    sh('docker system prune --all --force --volumes || :')

@timeout(25)
@step()
def clone_repo(gitBase="", branch="", ignorePullRequest="", repo=""):
    sh("git clone --depth 1 {}/{}".format(gitBase, repo))

@step()
def retrieve_code():
    """Retrieve Code"""
    gitBase = "https://github.com/kubic-project"
    branch = getvar('CHANGE_TARGET')
    ignorePullRequest = False
    # TODO: parallel
    clone_repo(gitBase=gitBase, branch=branch, ignorePullRequest=ignorePullRequest, repo="automation")
    clone_repo(gitBase=gitBase, branch=branch, ignorePullRequest=ignorePullRequest, repo="salt")
    clone_repo(gitBase=gitBase, branch=branch, ignorePullRequest=ignorePullRequest, repo="velum")
    clone_repo(gitBase=gitBase, branch=branch, ignorePullRequest=ignorePullRequest, repo="caasp-container-manifests")
    clone_repo(gitBase=gitBase, branch=branch, ignorePullRequest=ignorePullRequest, repo="caasp-services")


@timeout(90)
@step()
def github_collaborator_check():
    print("Starting GitHub Collaborator Check")
    org = "kubic-project"
    repo = 'salt'
    user = getvar('CHANGE_AUTHOR')
    token = os.getenv('GITHUB_TOKEN')
    url = "https://api.github.com/repos/{}/{}/collaborators/{}"
    url = url.format(org, repo, user)
    if user is "":
        return

    # Check if a change is from collaborator, or not.
    # Require approval for non-collaborators. As non-collaborators are
    # already considered untrusted by Jenkins, Jenkins will load the
    # Pipeline and library from the target branch and NOT from the
    # outside collaborators fork / pull request.
    headers = {
        "Accept": "application/vnd.github.hellcat-preview+json",
        "Authorization": "token {}".format(token),
    }
    r = requests.get(url, headers=headers)
    # 204 yes, 404 no   :-/
    if r.status_code == 204:
        print("Test execution for collaborator {} allowed".format(user))
        return

    msg = "Test execution for unknown user {} NOT allowed".format(user)
    print(msg)
    raise Exception(msg)


@step()
def create_environment():
    """Create Environment"""
    if conf.stack_type == 'caasp-kvm':
        # TODO ${extraRepo}
        vanilla_flag = " --vanilla " if conf.vanilla else ""

        shp("automation/caasp-kvm",
            "./caasp-kvm -L ${netlocation} " + vanilla_flag +
            " --build -m ${master_count} -w ${worker_count} "
            "--image ${image} --velum-image channel://${channel}"
            " --admin-ram ${admin_ram} --admin-cpu ${admin_cpu}"
            " --master-ram ${master_ram} --master-cpu ${master_cpu}"
            " --worker-ram ${worker_ram} --worker-cpu ${worker_cpu}"
        )
        sh("cp ${WORKSPACE}/automation/caasp-kvm/environment.json ${WORKSPACE}/")
    elif conf.stack_type == 'openstack':
        # FIXME
        raise NotImplementedError
    elif conf.stack_type == 'bare-metal':
        shp("${WORKSPACE}/automation/caasp-bare-metal/deployer",
            "./deployer ${JOB_NAME}-${BUILD_NUMBER} --admin "
            "--master-count 1 --worker-count 3"
            " --conffile deployer.conf.json")
        sh("cp ${WORKSPACE}/automation/caasp-bare-metal/deployer/environment.json ${WORKSPACE}/")

    sh("cat ${WORKSPACE}/environment.json")

@step()
def install_netdata():
    """Deploy CI Tools"""
    sh("${WORKSPACE}/automation/misc-tools/netdata/install admin")

@timeout(90)
@step()
def configure_environment():
    """Configure Environment"""

    cmd = "./velum-interactions --configure --enable-tiller --environment ${WORKSPACE}/environment.json"
    if getvar("CHOOSE_CRIO").lower() == "true":
        cmd += " --choose_crio"
    shp('automation/velum-bootstrap', cmd)
    #junit "velum-bootstrap.xml"
    archive_artifacts('automation/velum-bootstrap', "screenshots/**")

@timeout(10)
@step()
def start_monitor_logs():
    sh_fork(
        "${WORKSPACE}/automation/misc-tools/parallel-ssh "
        "-e ${WORKSPACE}/environment.json "
        "-i ${WORKSPACE}/automation/misc-files/id_shared all "
        "-- journalctl -f"
    )

@timeout(10)
@step()
def stop_monitor_logs():
    # on teardown, call --stop to terminate the runner
    sh("${WORKSPACE}/automation/misc-tools/parallel-ssh --stop "
       "-e ${WORKSPACE}/environment.json "
       "-i ${WORKSPACE}/automation/misc-files/id_shared all "
       "-- journalctl -f")

@timeout(90)
@step()
def setup_velum_interactions():
    # TODO: this installs packages
    shp('automation/velum-bootstrap', './velum-interactions --setup')


@timeout(125)
@step()
def wait_for_velum():
    shp('automation/misc-tools',
        "${VENVDIR}/bin/python3 ./wait-for-velum https://$(jq '.minions[0].addresses.publicIpv4' -r ${WORKSPACE}/environment.json) --timeout 2")


@timeout(600)
@step()
def bootstrap_environment():
    """Bootstrap Environment"""
    start_monitor_logs()
    sh("chmod 400 ${WORKSPACE}/automation/misc-files/id_shared")
    shp('automation/velum-bootstrap', "./velum-interactions --bootstrap"
        " --environment ${WORKSPACE}/environment.json")
    stop_monitor_logs()
    archive_artifacts('automation/velum-bootstrap', "screenshots/**")
    archive_artifacts('automation/velum-bootstrap', "kubeconfig")

@timeout(20)
@step()
def fetch_kubeconfig():
    shp('automation/velum-bootstrap',
        "./velum-interactions --download-kubeconfig"
        " --environment ${WORKSPACE}/environment.json")
    shp('automation/velum-bootstrap',
        "cp kubeconfig ${WORKSPACE}/kubeconfig")

@step()
def retrieve_image():
    if conf.stack_type == 'bare-metal':
        shp('automation/caasp-bare-metal/deployer',
            "./deployer ${JOB_NAME}-${BUILD_NUMBER} --start-iso-fetching"
            " --conffile deployer.conf.json")
        shp('automation/caasp-bare-metal/deployer',
            "./deployer ${JOB_NAME}-${BUILD_NUMBER} --wait-iso-fetching"
            " --conffile deployer.conf.json")
    else:
        shp(
            "automation/misc-tools",
            "./download-image --location ${netlocation}"
            " --type kvm channel://${channel}")

@step()
def create_environment_workers_bare_metal():
    # Warning: requires deployer.conf.json
    shp('automation/caasp-bare-metal/deployer',
        './deployer ${JOB_NAME}-${BUILD_NUMBER} --deploy-nodes --logsdir ${WORKSPACE}/logs'
        " --conffile deployer.conf.json")
    shp('automation/caasp-bare-metal/deployer',
        "cp environment.json ${WORKSPACE}/environment.json")
    shp('automation/caasp-bare-metal/deployer',
        '${WORKSPACE}/automation/misc-tools/generate-ssh-config ${WORKSPACE}/environment.json')
    archive_artifacts('${WORKSPACE}', 'environment.json')


@step()
def create_environment_workers():
    """Create Environment Workers"""
    if conf.stack_type == 'bare-metal':
        create_environment_workers_bare_metal()

def load_env_json():
    with open(replace_vars("${WORKSPACE}/environment.json")) as f:
        return json.load(f)


@step()
def setup_testinfra_tox(env, cmd):
    shp("${WORKSPACE}/automation/testinfra", cmd, env=env)

@timeout(30)
@step()
def setup_testinfra():
    # sudo zypper in -y python-devel
    env = {
        "ENVIRONMENT_JSON": replace_vars("${WORKSPACE}/environment.json"),
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "SSH_CONFIG": replace_vars("${WORKSPACE}/automation/misc-tools/environment.ssh_config"),
    }
    shp("${WORKSPACE}/automation/testinfra", "tox -l")

    if conf.dryrun:
        print("DRYRUN: skipping setup_testinfra_tox()")
        return

    cmds = {
        "tox -e {role}-{status} --notest".format(**minion)
        for minion in load_env_json()["minions"]
    } # avoid unneded runs
    for cmd in cmds:
        setup_testinfra_tox(env, cmd)


@timeout(30 * 10) # implement parallel run
@step()
def run_testinfra():
    env = {
        "ENVIRONMENT_JSON": replace_vars("${WORKSPACE}/environment.json"),
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "SSH_CONFIG": replace_vars("${WORKSPACE}/automation/misc-tools/environment.ssh_config"),
    }
    if conf.dryrun:
        print("DRYRUN: skipping tox run")
        return

    for minion in load_env_json()["minions"]:
        cmd = "tox -e {role}-{status} --notest".format(**minion)
        cmd = "tox -e {role}-{status} -- --hosts {fqdn} --junit-xml" \
           " testinfra-{role}-{index}.xml -v".format(**minion)
        shp("${WORKSPACE}/automation/testinfra", cmd, env=env)

    #junit "testinfra-${minion.role}-${minion.index}.xml"



@timeout(600)
@step()
def k8s_create_pod(env):
    # FIXME: avoid manipulating PATH
    sh("${WORKSPACE}/automation/k8s-pod-tests/k8s-pod-tests -k"
       " ${WORKSPACE}/kubeconfig"
       " -c ${WORKSPACE}/automation/k8s-pod-tests/yaml/${podname}.yml",
       env=env)

@timeout(600)
@step()
def k8s_test_scaleup(env):
    sh("${WORKSPACE}/automation/k8s-pod-tests/k8s-pod-tests"
       " -k ${WORKSPACE}/kubeconfig --wait --slowscale ${podname}"
       " ${replica_count} ${replicas_creation_interval_seconds}",
       env=env)

@timeout(600)
@step()
def k8s_teardown(env):
    sh("${WORKSPACE}/automation/k8s-pod-tests/k8s-pod-tests"
       " -k ${WORKSPACE}/kubeconfig"
       " -d ${WORKSPACE}/automation/k8s-pod-tests/yaml/${podname}.yml",
       env=env)

@timeout(5)
@step()
def k8s_show_running_pods(env):
    """Show running pods"""
    sh("${WORKSPACE}/automation/k8s-pod-tests/k8s-pod-tests"
       " -k ${WORKSPACE}/kubeconfig -l", env=env)

@step()
def run_k8s_pod_tests():
    env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:~/bin",
        "KUBECONFIG": replace_vars("${WORKSPACE}/kubeconfig")
    }
    sh("wc -l ${WORKSPACE}/kubeconfig")
    sh("${WORKSPACE}/automation/k8s-pod-tests/k8s-pod-tests"
       " -k ${WORKSPACE}/kubeconfig -l", env=env)

    k8s_create_pod(env)
    k8s_show_running_pods(env)
    k8s_test_scaleup(env)
    k8s_teardown(env)

@timeout(300)
@step()
def install_helm_client():
    env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:~/bin",
        "KUBECONFIG": replace_vars("${WORKSPACE}/kubeconfig")
    }
    sh("env", env=env)
    sh("kubectl get namespaces", env=env)
    sh("set -o pipefail; kubectl get namespaces | grep kube-system", env=env)
    sh("set -o pipefail;"
       " kubectl get serviceaccounts --namespace kube-system |grep tiller",
       env=env)
    sh("set -o pipefail;"
       " kubectl get pods --namespace kube-system"
       " --kubeconfig=${WORKSPACE}/kubeconfig  | grep tiller-deploy ",
       env=env)

    # This whole thing is a hack, we should be using our builds of the
    # helm client.
    url = "https://kubernetes-helm.storage.googleapis.com/helm-v2.8.2-linux-amd64.tar.gz"
    sh("mkdir -p ${WORKSPACE}/tmp")
    sh("wget -N -O ${WORKSPACE}/tmp/helm.tar.gz " + url)
    sh("tar --directory ${WORKSPACE}/tmp -xzvf ${WORKSPACE}/tmp/helm.tar.gz")
    sh("mv ${WORKSPACE}/tmp/linux-amd64/helm ${WORKSPACE}/helm")
    sh("${WORKSPACE}/helm --home ${WORKSPACE}/.helm init --client-only")
    sh("${WORKSPACE}/helm --home ${WORKSPACE}/.helm repo update")

@timeout(125)
@step()
def add_node():
    shp('automation/velum-bootstrap',
        './velum-interactions --node-add " \
        "--environment ${WORKSPACE}/environment.json')
    #junit "velum-bootstrap.xml"
    archive_artifacts('automation/velum-bootstrap', "screenshots/**")
    archive_artifacts('automation/velum-bootstrap', "kubeconfig")


@step()
def run_conformance_tests():
    """Run K8S Conformance Tests"""
    # TODO
    pass

@step()
def transactional_update():
    """Run transactional update"""
    for minion in load_env_json()["minions"]:
        ssh(minion, 'systemctl disable --now transactional-update.timer')
        ssh(minion, '/usr/sbin/transactional-update cleanup dup salt')

@step()
def upgrade_environment_stage_1():
    admin = [m for m in load_env_json()["minions"] if m["role"] == "admin"][0]

    if conf.fake_update_is_available:
        # Fake the need for updates
        ssh(admin, "docker exec -i \$(docker ps | grep salt-master "
            "| awk '{print \$1}') salt '*' "
            "grains.setval tx_update_reboot_needed true")

    # Refresh Salt Grains
    ssh(admin, "docker exec -i \$(docker ps | grep salt-master | "
        "awk '{print \$1}') salt '*' saltutil.refresh_grains")

    # Perform the upgrade
    #start_monitor_logs()
    shp('automation/velum-bootstrap', "./velum-interactions --update-admin "
        "--environment ${WORKSPACE}/environment.json")
    #stop_monitor_logs()

@step()
def upgrade_environment_stage_2():

    #start_monitor_logs()
    shp('automation/velum-bootstrap',
        "./velum-interactions --update-minions --environment "
        "${WORKSPACE}/environment.json")
    #stop_monitor_logs()

    # save old kubeconfig first
    shp('automation/velum-bootstrap',
        "mv ${WORKSPACE}/kubeconfig ${WORKSPACE}/kubeconfig.old")
    fetch_kubeconfig()
    shp('automation/velum-bootstrap',
        "diff -u ${WORKSPACE}/kubeconfig.old ${WORKSPACE}/kubeconfig || :")


@step()
def gather_netdata_metrics():
    """Gather Netdata metrics"""
    sh("${WORKSPACE}/automation/misc-tools/netdata/capture/capture-charts"
       " admin --outdir ${WORKSPACE}/netdata/admin"
       " -l ${WORKSPACE}/logs/netdata-capture-admin.log")

@step()
def ssh(minion, script):
    sh("ssh -F ${WORKSPACE}/automation/misc-tools/environment.ssh_config" +
       " {} -- \"{}\"".format(minion["fqdn"], script))

@step()
def scp(minion, src, dst):
    sh("scp -F ${WORKSPACE}/automation/misc-tools/environment.ssh_config" +
       " {}:{} {}".format(minion["fqdn"], src, dst))

@timeout(300)
@step()
def _gather_logs(minion):
    ssh(minion, "supportconfig -b")
    scp(minion, "/var/log/nts_*.tbz", replace_vars("${WORKSPACE}/logs/"))

@step()
def gather_logs():
    """Gather Kubic Logs"""
    if conf.dryrun:
        print("DRYRUN: skipping gather_logs")
        return

    # TODO: parallel
    for minion in load_env_json()["minions"]:
        _gather_logs(minion)

    extract_salt_events()

@timeout(10)
@step()
def extract_salt_events():
    """Extract failed Salt events from supportconfig tarballs"""
    print("Note: tar 'Not found in archive' errors should be ignored")
    try:
        shp("${WORKSPACE}/logs",
            "find . -name 'nts_*.tbz' -print0 | "
            "xargs -I ! -0 tar --wildcards --strip-components=1 "
            "-xf ! */salt-events.json */salt-events-summary.txt")
    except:
        pass


def archive_artifacts(path, glob):
    sh("mkdir -p ${WORKSPACE}/artifacts")
    path = os.path.join(path, glob)
    try:
        sh("rsync -a " + path + " ${WORKSPACE}/artifacts")
    except:
        print("rsync error")

@step()
def archive_logs():
    """Archive Logs"""
    archive_artifacts('${WORKSPACE}', 'logs/**')
    archive_artifacts('${WORKSPACE}', 'netdata/**')

@timeout(15)
@step()
def cleanup_kvm():
    shp('automation/caasp-kvm',
        "./caasp-kvm --destroy")


@timeout(30)
@step()
def cleanup_openstack():
    # TODO: set stackName, OPENRC variable, retry 10 times
    raise NotImplementedError
    shp('automation/caasp-openstack-heat',
        "./caasp-openstack --openrc ${OPENRC} --name ${stackName} -d")


@timeout(30)
@step()
def cleanup_bare_metal():
    shp('automation/caasp-bare-metal/deployer',
        './deployer --release ${JOB_NAME}-${BUILD_NUMBER}'
             " --conffile deployer.conf.json")

@timeout(30)
@step()
def cleanup_hyperv():
    # TODO
    raise NotImplementedError


@step()
def final_cleanup():
    """Cleanup"""
    if conf.stack_type == 'caasp-kvm':
        cleanup_kvm()
    elif conf.stack_type == 'openstack':
        cleanup_openstack()
    elif conf.stack_type == 'bare-metal':
        cleanup_bare_metal()


def parse_args():
    """Handle free-form CLI parameters
    """
    conf = Namespace()
    conf.dryrun = False
    conf.stack_type = 'caasp-kvm'
    conf.change_author = ""
    conf.no_checkout = False
    conf.no_collab_check = False
    conf.no_destroy = False
    conf.upgrade_environment = False
    conf.fake_update_is_available = False
    conf.workers = "3"
    conf.job_name = "myjob"
    conf.build_number = "000"
    conf.master_count = "3"
    conf.worker_count = "3"
    conf.admin_cpu = "4"
    conf.admin_ram = "8192"
    conf.master_cpu = "4"
    conf.master_ram = "4096"
    conf.worker_cpu = "4"
    conf.worker_ram = "4096"
    conf.vanilla = False
    conf.netlocation = "provo"
    conf.channel = "devel"
    conf.replica_count = "5"
    conf.replicas_creation_interval_seconds = "5"
    conf.podname = "default"
    conf.image = replace_vars("file://${WORKSPACE}/automation/downloads/kvm-devel")

    if '-h' in sys.argv or '--help' in sys.argv:
        print("Help:\n\n")
        print(help)
        print("\nSupported options:\n")
        for k, v in sorted(conf.__dict__.items()):
            k = k.replace('_', '-')
            if v == False:
                print("    {}".format(k))
            else:
                print("    {}={}".format(k, v))
        print()
        sys.exit()

    for a in sys.argv[1:]:
        if '=' in a:
            # extract key-value args
            k, v = a.split('=', 1)[0:2]
        else:
            k, v = a, True

        k = k.replace('-', '_')
        if k in conf:
            conf.__setattr__(k, v)
        else:
            print("Unexpected conf param {}".format(k))
            sys.exit(1)

    return conf

def check_root_user():
    if os.getenv('EUID') != "0":
        print("Error: this script needs to be run as root")
        sys.exit(1)

def main():
    global conf
    print("Testrunner v. {}".format(__version__))
    conf = parse_args()

    print("Using workspace: {}".format(getvar("WORKSPACE")))
    print("Conf: {}".format(conf))
    print("PATH: {}".format(os.getenv("PATH")))

    if not conf.dryrun:
        create_workspace_dir()
    info()
    if not conf.no_checkout and not conf.no_collab_check:
        github_collaborator_check()
    initial_cleanup()
    if not conf.no_checkout:
        retrieve_code()
    retrieve_image()
    create_environment()
    install_netdata()
    setup_velum_interactions()
    configure_environment()
    create_environment_workers()
    bootstrap_environment()

    setup_testinfra()
    run_testinfra()

    fetch_kubeconfig()
    install_helm_client()
    run_k8s_pod_tests()

    gather_netdata_metrics()
    gather_logs()
    archive_logs()
    if conf.upgrade_environment:
        transactional_update()
        upgrade_environment_stage_1()
        upgrade_environment_stage_2()
    if not conf.no_destroy:
        final_cleanup()

if __name__ == '__main__':
    main()
