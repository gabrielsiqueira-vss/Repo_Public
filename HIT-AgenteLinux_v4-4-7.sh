#!/bin/bash
#HIT - Instalação Agente Linux

#Repositorios

##CentOS
repoCentosV5="http://repo.zabbix.com/zabbix/4.4/rhel/5/x86_64/zabbix-agent-4.4.7-1.el5.x86_64.rpm"
repoCentosV6="http://repo.zabbix.com/zabbix/4.4/rhel/6/x86_64/zabbix-agent-4.4.7-1.el6.x86_64.rpm"
repoCentosV7="http://repo.zabbix.com/zabbix/4.4/rhel/7/x86_64/zabbix-agent-4.4.7-1.el7.x86_64.rpm"
repoCentosV8="http://repo.zabbix.com/zabbix/4.4/rhel/8/x86_64/zabbix-agent-4.4.7-1.el8.x86_64.rpm"
repoCentosV9="https://repo.zabbix.com/zabbix/5.0/rhel/9/x86_64/zabbix-agent-5.0.42-1.el9.x86_64.rpm"

instCentosV5=zabbix-agent-4.4.7-1.el5.x86_64
instCentosV6=zabbix-agent-4.4.7-1.el6.x86_64
instCentosV7=zabbix-agent-4.4.7-1.el7.x86_64
instCentosV8=zabbix-agent-4.4.7-1.el8.x86_64
instCentosV9=zabbix-agent-5.0.42-1.el9.x86_64

##Ubuntu
repoBionic64="http://repo.zabbix.com/zabbix/4.4/ubuntu/pool/main/z/zabbix/zabbix-agent_4.4.7-1%2Bbionic_amd64.deb"
repoBionic32="http://repo.zabbix.com/zabbix/4.4/ubuntu/pool/main/z/zabbix/zabbix-agent_4.4.7-1%2Bbionic_i386.deb"
repoTrusty64="http://repo.zabbix.com/zabbix/4.4/ubuntu/pool/main/z/zabbix/zabbix-agent_4.4.7-1%2Btrusty_amd64.deb"
repoTrusty32="http://repo.zabbix.com/zabbix/4.4/ubuntu/pool/main/z/zabbix/zabbix-agent_4.4.7-1%2Btrusty_i386.deb"
repoXenial64="http://repo.zabbix.com/zabbix/4.4/ubuntu/pool/main/z/zabbix/zabbix-agent_4.4.7-1%2Bxenial_amd64.deb"
repoXenial32="http://repo.zabbix.com/zabbix/4.4/ubuntu/pool/main/z/zabbix/zabbix-agent_4.4.7-1%2Bxenial_i386.deb"
repoFocal="https://repo.zabbix.com/zabbix/4.4/ubuntu/pool/main/z/zabbix-release/zabbix-release_4.4-1%2Bfocal_all.deb"
repoJammy="https://repo.zabbix.com/zabbix/5.0/ubuntu/pool/main/z/zabbix/zabbix-agent_5.0.42-1%2Bubuntu22.04_amd64.deb"
repoNoble="https://repo.zabbix.com/zabbix/5.0/ubuntu/pool/main/z/zabbix/zabbix-agent_5.0.42-1%2Bubuntu24.04_amd64.deb"

instBionic64=zabbix-agent_4.4.7-1+bionic_amd64.deb
instBionic32=zabbix-agent_4.4.7-1+bionic_i386.deb
instTrusty64=zabbix-agent_4.4.7-1+trusty_amd64.deb
instTrusty32=zabbix-agent_4.4.7-1+trusty_i386.deb
instXenial64=zabbix-agent_4.4.7-1+xenial_amd64.deb
instXenial32=zabbix-agent_4.4.7-1+xenial_i386.deb
instFocal=zabbix-release_4.4-1+focal_all.deb
instJammy=zabbix-agent_5.0.42-1+ubuntu22.04_amd64.deb
instNoble=zabbix-agent_5.0.42-1+ubuntu24.04_amd64.deb

##Debian
repoJessie64="http://repo.zabbix.com/zabbix/4.4/debian/pool/main/z/zabbix/zabbix-agent_4.4.7-1%2Bjessie_amd64.deb"
repoJessie32="http://repo.zabbix.com/zabbix/4.4/debian/pool/main/z/zabbix/zabbix-agent_4.4.7-1%2Bjessie_i386.deb"
repoStretch64="http://repo.zabbix.com/zabbix/4.4/debian/pool/main/z/zabbix/zabbix-agent_4.4.7-1%2Bstretch_amd64.deb"
repoStretch32="http://repo.zabbix.com/zabbix/4.4/debian/pool/main/z/zabbix/zabbix-agent_4.4.7-1%2Bstretch_i386.deb"
repoBuster64="http://repo.zabbix.com/zabbix/4.4/debian/pool/main/z/zabbix/zabbix-agent_4.4.7-1%2Bbuster_amd64.deb"
repoBuster32="http://repo.zabbix.com/zabbix/4.4/debian/pool/main/z/zabbix/zabbix-agent_4.4.7-1%2Bbuster_i386.deb"
repoWheezy64="http://repo.zabbix.com/zabbix/3.4/debian/pool/main/z/zabbix/zabbix-agent_3.4.10-1%2Bwheezy_amd64.deb"
repoWheezy32="http://repo.zabbix.com/zabbix/3.4/debian/pool/main/z/zabbix/zabbix-agent_3.4.10-1%2Bwheezy_i386.deb"
repoBullseye="https://repo.zabbix.com/zabbix/5.0/debian/pool/main/z/zabbix/zabbix-agent_5.0.15-1%2Bbullseye_amd64.deb"

instJessie64=zabbix-agent_4.4.7-1+jessie_amd64.deb
instJessie32=zabbix-agent_4.4.7-1+jessie_i386.deb
instStretch64=zabbix-agent_4.4.7-1+stretch_amd64.deb
instStretch32=zabbix-agent_4.4.7-1+stretch_i386.deb
instBuster64=zabbix-agent_4.4.7-1+buster_amd64.deb
instBuster32=zabbix-agent_4.4.7-1+buster_i386.deb
instWheezy64=zabbix-agent_3.4.10-1+wheezy_amd64.deb
instWheezy32=zabbix-agent_3.4.10-1+wheezy_i386.deb
instBullseye=zabbix-agent_5.0.15-1+bullseye_amd64.deb

##Suse
repoSuse12x64="https://repo.zabbix.com/zabbix/4.4/sles/12/x86_64/zabbix-agent-4.4.7-1.el12.x86_64.rpm"
repoSuse15x64="https://repo.zabbix.com/zabbix/4.4/sles/15/x86_64/zabbix-agent-4.4.7-1.el15.x86_64.rpm"
instSuse12x64=zabbix-agent-4.4.7-1.el12.x86_64.rpm
instSuse15x64=zabbix-agent-4.4.7-1.el15.x86_64.rpm

checkZabbixAgentInstalled() {
    return 1
    if rpm -q zabbix-agent >/dev/null 2>&1 || dpkg -l | grep -q zabbix-agent >/dev/null 2>&1; then
        echo "Zabbix Agent já está instalado."
        if command -v zabbix_agentd >/dev/null 2>&1; then
			agent_conf_path=$(find / -name zabbix_agentd.conf 2>/dev/null | grep -v 'Permission denied')
            if [ -n "$agent_conf_path" ]; then
                echo "Caminho do arquivo de configuração do Zabbix Agent: $agent_conf_path"
            else
                echo "Não foi possível encontrar o arquivo de configuração do Zabbix Agent."
            fi
        else
            echo "Não foi possível determinar o caminho de instalação do Zabbix Agent."
        fi
        return 0
    else
        echo "Zabbix Agent não está instalado."
        return 1
    fi
}

getZabbixAgentVersion() {
    if command -v zabbix_agentd >/dev/null 2>&1; then
        version=$(zabbix_agentd -V 2>&1 | grep -oP 'v?\d+\.\d+\.\d+' | head -1)
    elif command -v zabbix_agent >/dev/null 2>&1; then
        version=$(zabbix_agent -V 2>&1 | grep -oP 'v?\d+\.\d+\.\d+' | head -1)
    else
        version=""
    fi

    if [[ -n "$version" ]]; then
        echo "$version" | cut -d. -f1
    else
        echo ""
    fi
}

adjustZabbixAgentRemoteCommands() {
    version_output=$(zabbix_agentd -V 2>/dev/null | grep -oP 'v?\d+\.\d+\.\d+' | head -1)
    
    if [[ $? -eq 0 && -n "$version_output" ]]; then
        major_version=$(echo "$version_output" | cut -d. -f1)
        
        if [[ $major_version -ge 5 ]]; then
            echo "Versão do Zabbix Agent >= 5. Ajustando /etc/zabbix/zabbix_agentd.conf para permitir comandos remotos."
            if ! grep -q "^AllowKey=system.run[*]" /etc/zabbix/zabbix_agentd.conf; then
                echo "AllowKey=system.run[*]" >> /etc/zabbix/zabbix_agentd.conf
            fi
        else
            echo "Versão do Zabbix Agent < 5. Ajustando /etc/zabbix/zabbix_agentd.conf para permitir comandos remotos."
            
            if grep -q "^[[:space:]]*#\?[[:space:]]*EnableRemoteCommands=" /etc/zabbix/zabbix_agentd.conf; then
                sed -i 's/^[[:space:]]*#\?[[:space:]]*EnableRemoteCommands=.*/EnableRemoteCommands=1/' /etc/zabbix/zabbix_agentd.conf
            else
                echo "EnableRemoteCommands=1" >> /etc/zabbix/zabbix_agentd.conf
            fi
        fi
    else
        echo "Erro: Zabbix Agent não está instalado ou não foi possível determinar a versão."
    fi
}

restart_service() {
    local service_name="$1"
    echo "Reiniciando o serviço $service_name"
    echo
    if service "$service_name" restart; then
        echo "Sucesso: O serviço $service_name foi reiniciado com sucesso"
        echo
    else
        echo "Erro: Falha ao reiniciar o serviço $service_name"
        echo
        return 1
    fi
}

adjustZabbixAgentConfig() {
    local ip_proxy="$1"
    local hostname="$2"
    local org_code="$3"
    local zabbix_agent_conf="/etc/zabbix/zabbix_agentd.conf"
    
	sed -i "s/^Server=\(.*\)/Server=\1,$ip_proxy/" "$zabbix_agent_conf"
    sed -i "s/^ServerActive=\(.*\)/ServerActive=\1,$ip_proxy/" "$zabbix_agent_conf"
    sed -i "s/^Hostname=.*/Hostname=$hostname"_"$org_code/" "$zabbix_agent_conf"

	adjustZabbixAgentRemoteCommands
}

configuraPortaZabbix() {
    PORTA=10050
    # FIREWALL: Detecta firewall ativo e adiciona a regra
    echo "Configurando Firewall..."
    # Firewalld
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --add-port=${PORTA}/tcp
        firewall-cmd --reload
        echo "Porta $PORTA adicionada ao firewalld"

    # UFW
    elif command -v ufw >/dev/null 2>&1 && systemctl is-active --quiet ufw; then
        ufw allow ${PORTA}/tcp
        echo "Porta $PORTA liberada no ufw"

    # IPTables
    elif command -v iptables >/dev/null 2>&1; then
        iptables -I INPUT -p tcp --dport ${PORTA} -j ACCEPT
        iptables -I OUTPUT -p tcp --sport ${PORTA} -j ACCEPT

        if command -v service >/dev/null 2>&1; then
            service iptables save 2>/dev/null || echo "Aviso: Não foi possível salvar regras do iptables"
        fi
        echo "Porta $PORTA liberada no iptables"

    else
        echo "Nenhum firewall compatível encontrado (iptables/firewalld/ufw)"
    fi

    echo "Configurando SELinux..."

    if command -v getenforce >/dev/null 2>&1; then
        STATUS=$(getenforce)

        if [ "$STATUS" != "Disabled" ]; then
            if command -v setsebool >/dev/null 2>&1; then
                echo "SELinux ativo ($STATUS)"
                setsebool -P zabbix_can_network=1
                echo "SELinux configurado com sucesso"
            else
                echo "setsebool não encontrado."
            fi
        else
            echo "SELinux está desativado. Nada a fazer."
        fi
    else
        echo "SELinux não está instalado neste sistema."
    fi
}


checkOS(){
	echo "Verificando versao e distribuicao do Sistema Operacional"
	distroLinux="$(cat /etc/*release)"
	osLinux="0"
	versLinux="0"
	arcLinux="$(arch)"

    echo ""
    echo "Distribuicao Linux detectada: $distroLinux"
    echo "Arquitetura do sistema detectada: $arcLinux"
    echo ""
	
	#CentOS
	if [[ $distroLinux == *"CentOS"* ]] || [[ $distroLinux == *"Hat"* ]] || [[ $distroLinux == *"Oracle Linux"* ]]; then
		osLinux="Rhel"
		
		if [[ $distroLinux == *"7"* ]]; then
			instalaCentOS $repoCentosV7 $instCentosV7
		elif [[ $distroLinux == *"6"* ]]; then
			instalaCentOS $repoCentosV6 $instCentosV6
		elif [[ $distroLinux == *"5"* ]]; then
			instalaCentOS $repoCentosV5 $instCentosV5
		elif [[ $distroLinux == *"8"* ]]; then
			instalaCentOS $repoCentosV8 $instCentosV8
		elif [[ $distroLinux == *"9"* ]]; then
			instalaCentOS $repoCentosV9 $instCentosV9
		else
            echo "Versao do SO nao suportada."
			return 1
		fi
	
	#Ubuntu
	elif [[ $distroLinux == *"Ubuntu"* ]]; then
		if [[ $distroLinux == *"bionic"* ]]; then
			if [[ $arcLinux == *"x86_64"* ]]; then
				instalaDebianUbuntu $repoBionic64 $instBionic64
			else
				instalaDebianUbuntu $repoBionic32 $instBionic32
			fi
		elif [[ $distroLinux == *"trusty"* ]]; then
			if [[ $arcLinux == *"x86_64"* ]]; then
				instalaDebianUbuntu $repoTrusty64 $instTrusty64
			else
				instalaDebianUbuntu $repoTrusty32 $instTrusty32
			fi
		elif [[ $distroLinux == *"xenial"* ]]; then
			if [[ $arcLinux == *"x86_64"* ]]; then
				instalaDebianUbuntu $repoXenial64 $instXenial64
			else
				instalaDebianUbuntu $repoXenial32 $instXenial32
			fi
		elif [[ $distroLinux == *"focal"* ]]; then
			instalaDebianUbuntu $repoFocal $instFocal
			aptInstallAgent
		elif [[ $distroLinux == *"jammy"* ]]; then
			instalaDebianUbuntu $repoJammy $instJammy
			aptInstallAgent
		elif [[ $distroLinux == *"noble"* ]]; then
			instalaDebianUbuntu $repoNoble $instNoble
			aptInstallAgent
		else
            echo "Versao do SO nao suportada."
			return 1
		fi
	
	#Debian
	elif [[ $distroLinux == *"Debian"* ]]; then
		osLinux="Debian"
		if [[ $distroLinux == *"jessie"* ]]; then
			if [[ $arcLinux == *"x86_64"* ]]; then
				instalaDebianUbuntu $repoJessie64 $instJessie64
			else
				instalaDebianUbuntu $repoJessie32 $instJessie32
			fi
		elif [[ $distroLinux == *"stretch"* ]]; then
			if [[ $arcLinux == *"x86_64"* ]]; then
				instalaDebianUbuntu $repoJessie64 $instJessie64
			else
				instalaDebianUbuntu $repoJessie32 $instJessie32
			fi
		elif [[ $distroLinux == *"buster"* ]]; then
			if [[ $arcLinux == *"x86_64"* ]]; then
				instalaDebianUbuntu $repoBuster64 $instBuster64
			else
				instalaDebianUbuntu $repoBuster32 $instBuster32
			fi
		elif [[ $distroLinux == *"wheezy"* ]]; then
			if [[ $arcLinux == *"x86_64"* ]]; then
				instalaDebianUbuntu $repoWheezy64 $instWheezy64
			else
				instalaDebianUbuntu $repoWheezy32 $instWheezy32
			fi
		elif [[ $distroLinux == *"bullseye"* ]]; then
			instalaDebianUbuntu $repoBullseye $instBullseye
		else
            echo "Versao do SO nao suportada."
			return 1
		fi
	
	#Suse
	elif [[ $distroLinux == *"Suse"* ]]; then
		osLinux="Suse"
		if [[ $distroLinux == *"12"* ]]; then
			instalaSuse $repoSuse12x64 $instSuse12x64
		elif [[ $distroLinux == *"15"* ]]; then
			instalaSuse $repoSuse15x64 $instSuse15x64
		else
            echo "Versao do SO nao suportada."
			return 1
		fi
	#Outro
	else
		return
	fi
	isSupported=true
	echo "Instalacao $osLinux $versLinux $arcLinux"
}

instalaCentOS(){
	echo "Fazendo download do pacote $1"
	rpm -ivh $1
	echo "Instalando pacote $2"
	yum install $2 -y
}

instalaDebianUbuntu(){
	echo "Fazendo download do pacote $1"
	wget --no-check-certificate $1
	echo "Instalando pacote $2"
	sudo dpkg -i $2
}

instalaSuse(){
	echo "Fazendo download do pacote $1"
	wget --no-check-certificate $1
	echo "Instalando pacote $2"
	rpm -ivh $2
}

aptInstallAgent(){
	apt install zabbix-agent
}

iniciaAgent(){
	echo "Iniciando o servico do Agente Zabbix"
	sudo service zabbix-agent start
	sudo service zabbix-agent enable
}

checkHostname(){
	echo "O hostname sera: $(hostname). Confirmar?(s/n)"
	read hostname
	if [[ $hostname == "s" ]]; then
		hostname="$(hostname)"
	elif [[ $hostname == "n" ]]; then
		echo "Digite o hostname:"
		read hostname
	else
		checkHostname
	fi
}

# versao #
echo "-- HIT - Instalacao Agente Linux --"
echo
isSupported=false

echo "Digite o código da organização"
read codOrg
echo
echo "Digite o IP do Proxy"
read ipProxy
echo
hostname="$(hostname)"
checkHostname
echo

configuraAgent(){
	major_version=$(getZabbixAgentVersion)
    if [[ -z "$major_version" ]]; then
        echo "Erro ao determinar a versão do Zabbix Agent. Configuração padrão será aplicada."
        enable_remote_command="EnableRemoteCommands=1"
    elif [[ $major_version -ge 5 ]]; then
        enable_remote_command="AllowKey=system.run[*]"
    else
        enable_remote_command="EnableRemoteCommands=1"
    fi

    echo "
# This is a configuration file for Zabbix agent daemon (Unix)
# To get more information about Zabbix, visit http://www.zabbix.com

############ GENERAL PARAMETERS #################

### Option: PidFile
#	Name of PID file.
#
# Mandatory: no
# Default:
# PidFile=/tmp/zabbix_agentd.pid

PidFile=/var/run/zabbix/zabbix_agentd.pid

### Option: LogType
#	Specifies where log messages are written to:
#		system  - syslog
#		file    - file specified with LogFile parameter
#		console - standard output
#
# Mandatory: no
# Default:
# LogType=file

### Option: LogFile
#	Log file name for LogType 'file' parameter.
#
# Mandatory: no
# Default:
# LogFile=

LogFile=/var/log/zabbix/zabbix_agentd.log

### Option: LogFileSize
#	Maximum size of log file in MB.
#	0 - disable automatic log rotation.
#
# Mandatory: no
# Range: 0-1024
# Default:
# LogFileSize=1

LogFileSize=10

### Option: DebugLevel
#	Specifies debug level:
#	0 - basic information about starting and stopping of Zabbix processes
#	1 - critical information
#	2 - error information
#	3 - warnings
#	4 - for debugging (produces lots of information)
#	5 - extended debugging (produces even more information)
#
# Mandatory: no
# Range: 0-5
# Default:
# DebugLevel=3

### Option: SourceIP
#	Source IP address for outgoing connections.
#
# Mandatory: no
# Default:
# SourceIP=

### Option: EnableRemoteCommands
#	Whether remote commands from Zabbix server are allowed.
#	0 - not allowed
#	1 - allowed
#
# Mandatory: no
# Default:
# EnableRemoteCommands=1
$enable_remote_command

### Option: LogRemoteCommands
#	Enable logging of executed shell commands as warnings.
#	0 - disabled
#	1 - enabled
#
# Mandatory: no
# Default:
# LogRemoteCommands=0

##### Passive checks related

### Option: Server
#	List of comma delimited IP addresses, optionally in CIDR notation, or hostnames of Zabbix servers and Zabbix proxies.
#	Incoming connections will be accepted only from the hosts listed here.
#	If IPv6 support is enabled then '127.0.0.1', '::127.0.0.1', '::ffff:127.0.0.1' are treated equally and '::/0' will allow any IPv4 or IPv6 address.
#	'0.0.0.0/0' can be used to allow any IPv4 address.
#	Example: Server=127.0.0.1,192.168.1.0/24,::1,2001:db8::/32,zabbix.domain
#
# Mandatory: no
# Default:
# Server=

Server=$ipProxy

### Option: ListenPort
#	Agent will listen on this port for connections from the server.
#
# Mandatory: no
# Range: 1024-32767
# Default:
# ListenPort=10050

### Option: ListenIP
#	List of comma delimited IP addresses that the agent should listen on.
#	First IP address is sent to Zabbix server if connecting to it to retrieve list of active checks.
#
# Mandatory: no
# Default:
# ListenIP=0.0.0.0

### Option: StartAgents
#	Number of pre-forked instances of zabbix_agentd that process passive checks.
#	If set to 0, disables passive checks and the agent will not listen on any TCP port.
#
# Mandatory: no
# Range: 0-100
# Default:
# StartAgents=3

##### Active checks related

### Option: ServerActive
#	List of comma delimited IP:port (or hostname:port) pairs of Zabbix servers and Zabbix proxies for active checks.
#	If port is not specified, default port is used.
#	IPv6 addresses must be enclosed in square brackets if port for that host is specified.
#	If port is not specified, square brackets for IPv6 addresses are optional.
#	If this parameter is not specified, active checks are disabled.
#	Example: ServerActive=127.0.0.1:20051,zabbix.domain,[::1]:30051,::1,[12fc::1]
#
# Mandatory: no
# Default:
# ServerActive=

ServerActive=$ipProxy

### Option: Hostname
#	Unique, case sensitive hostname.
#	Required for active checks and must match hostname as configured on the server.
#	Value is acquired from HostnameItem if undefined.
#
# Mandatory: no
# Default:
# Hostname=

Hostname=$hostname"_"$codOrg

### Option: HostnameItem
#	Item used for generating Hostname if it is undefined. Ignored if Hostname is defined.
#	Does not support UserParameters or aliases.
#
# Mandatory: no
# Default:
# HostnameItem=system.hostname

### Option: HostMetadata
#	Optional parameter that defines host metadata.
#	Host metadata is used at host auto-registration process.
#	An agent will issue an error and not start if the value is over limit of 255 characters.
#	If not defined, value will be acquired from HostMetadataItem.
#
# Mandatory: no
# Range: 0-255 characters
# Default:
# HostMetadata=

### Option: HostMetadataItem
#	Optional parameter that defines an item used for getting host metadata.
#	Host metadata is used at host auto-registration process.
#	During an auto-registration request an agent will log a warning message if
#	the value returned by specified item is over limit of 255 characters.
#	This option is only used when HostMetadata is not defined.
#
# Mandatory: no
# Default:
# HostMetadataItem=

### Option: RefreshActiveChecks
#	How often list of active checks is refreshed, in seconds.
#
# Mandatory: no
# Range: 60-3600
# Default:
# RefreshActiveChecks=120

### Option: BufferSend
#	Do not keep data longer than N seconds in buffer.
#
# Mandatory: no
# Range: 1-3600
# Default:
# BufferSend=5

### Option: BufferSize
#	Maximum number of values in a memory buffer. The agent will send
#	all collected data to Zabbix Server or Proxy if the buffer is full.
#
# Mandatory: no
# Range: 2-65535
# Default:
# BufferSize=100

### Option: MaxLinesPerSecond
#	Maximum number of new lines the agent will send per second to Zabbix Server
#	or Proxy processing 'log' and 'logrt' active checks.
#	The provided value will be overridden by the parameter 'maxlines',
#	provided in 'log' or 'logrt' item keys.
#
# Mandatory: no
# Range: 1-1000
# Default:
# MaxLinesPerSecond=20

############ ADVANCED PARAMETERS #################

### Option: Alias
#	Sets an alias for an item key. It can be used to substitute long and complex item key with a smaller and simpler one.
#	Multiple Alias parameters may be present. Multiple parameters with the same Alias key are not allowed.
#	Different Alias keys may reference the same item key.
#	For example, to retrieve the ID of user 'zabbix':
#	Alias=zabbix.userid:vfs.file.regexp[/etc/passwd,^zabbix:.:([0-9]+),,,,\1]
#	Now shorthand key zabbix.userid may be used to retrieve data.
#	Aliases can be used in HostMetadataItem but not in HostnameItem parameters.
#
# Mandatory: no
# Range:
# Default:

### Option: Timeout
#	Spend no more than Timeout seconds on processing
#
# Mandatory: no
# Range: 1-30
# Default:
Timeout=30

### Option: AllowRoot
#	Allow the agent to run as 'root'. If disabled and the agent is started by 'root', the agent
#	will try to switch to the user specified by the User configuration option instead.
#	Has no effect if started under a regular user.
#	0 - do not allow
#	1 - allow
#
# Mandatory: no
# Default:
# AllowRoot=0

### Option: User
#	Drop privileges to a specific, existing user on the system.
#	Only has effect if run as 'root' and AllowRoot is disabled.
#
# Mandatory: no
# Default:
# User=zabbix

### Option: Include
#	You may include individual files or all files in a directory in the configuration file.
#	Installing Zabbix will create include directory in /usr/local/etc, unless modified during the compile time.
#
# Mandatory: no
# Default:
# Include=

Include=/etc/zabbix/zabbix_agentd.d/*.conf

# Include=/usr/local/etc/zabbix_agentd.userparams.conf
# Include=/usr/local/etc/zabbix_agentd.conf.d/
# Include=/usr/local/etc/zabbix_agentd.conf.d/*.conf

####### USER-DEFINED MONITORED PARAMETERS #######

### Option: UnsafeUserParameters
#	Allow all characters to be passed in arguments to user-defined parameters.
#	The following characters are not allowed:
#
# Mandatory: no
# Range: 0-1
# Default:
# UnsafeUserParameters=0

### Option: UserParameter
#	User-defined parameter to monitor. There can be several user-defined parameters.
#	Format: UserParameter=<key>,<shell command>
#	See 'zabbix_agentd' directory for examples.
#
# Mandatory: no
# Default:
# UserParameter=

####### LOADABLE MODULES #######

### Option: LoadModulePath
#	Full path to location of agent modules.
#	Default depends on compilation options.
#
# Mandatory: no
# Default:
# LoadModulePath=${libdir}/modules

### Option: LoadModule
#	Module to load at agent startup. Modules are used to extend functionality of the agent.
#	Format: LoadModule=<module.so>
#	The modules must be located in directory specified by LoadModulePath.
#	It is allowed to include multiple LoadModule parameters.
#
# Mandatory: no
# Default:
# LoadModule=

####### TLS-RELATED PARAMETERS #######

### Option: TLSConnect
#	How the agent should connect to server or proxy. Used for active checks.
#	Only one value can be specified:
#		unencrypted - connect without encryption
#		psk         - connect using TLS and a pre-shared key
#		cert        - connect using TLS and a certificate
#
# Mandatory: yes, if TLS certificate or PSK parameters are defined (even for 'unencrypted' connection)
# Default:
# TLSConnect=unencrypted

### Option: TLSAccept
#	What incoming connections to accept.
#	Multiple values can be specified, separated by comma:
#		unencrypted - accept connections without encryption
#		psk         - accept connections secured with TLS and a pre-shared key
#		cert        - accept connections secured with TLS and a certificate
#
# Mandatory: yes, if TLS certificate or PSK parameters are defined (even for 'unencrypted' connection)
# Default:
# TLSAccept=unencrypted

### Option: TLSCAFile
#	Full pathname of a file containing the top-level CA(s) certificates for
#	peer certificate verification.
#
# Mandatory: no
# Default:
# TLSCAFile=

### Option: TLSCRLFile
#	Full pathname of a file containing revoked certificates.
#
# Mandatory: no
# Default:
# TLSCRLFile=

### Option: TLSServerCertIssuer
#      Allowed server certificate issuer.
#
# Mandatory: no
# Default:
# TLSServerCertIssuer=

### Option: TLSServerCertSubject
#      Allowed server certificate subject.
#
# Mandatory: no
# Default:
# TLSServerCertSubject=

### Option: TLSCertFile
#	Full pathname of a file containing the agent certificate or certificate chain.
#
# Mandatory: no
# Default:
# TLSCertFile=

### Option: TLSKeyFile
#	Full pathname of a file containing the agent private key.
#
# Mandatory: no
# Default:
# TLSKeyFile=

### Option: TLSPSKIdentity
#	Unique, case sensitive string used to identify the pre-shared key.
#
# Mandatory: no
# Default:
# TLSPSKIdentity=

### Option: TLSPSKFile
#	Full pathname of a file containing the pre-shared key.
#
# Mandatory: no
# Default:
# TLSPSKFile=

  " > /etc/zabbix/zabbix_agentd.conf
}

if ! checkZabbixAgentInstalled; then
	echo "Iniciando a instalacao do Zabbix Agent..."

    if ! checkOS; then
        echo "Sistema Operacional nao suportado. Abortando a instalacao do Zabbix Agent."
        exit 1
    fi

	echo
	echo "Configurando o agente Zabbix..."
	configuraAgent
	echo
	echo "Ajustando configurações do agente Zabbix..."
	adjustZabbixAgentRemoteCommands
	echo
	echo "Configurando firewall e SELinux..."
    configuraPortaZabbix
	echo
	echo "Iniciando o serviço do agente Zabbix..."
	iniciaAgent
    echo
	echo "Instalação concluída!"
	echo "Deseja abrir o arquivo de log?(s/n)"
	read openLog

	if [[ $openLog == "s" ]]; then
		tail -f /var/log/zabbix/zabbix_agentd.log
	fi

else
	echo "Zabbix Agent está instalado. Configurando o agente..."
	adjustZabbixAgentConfig "$ipProxy" "$hostname" "$codOrg"
	restart_service "zabbix-agent"
fi

