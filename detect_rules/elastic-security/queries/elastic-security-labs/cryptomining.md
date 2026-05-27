<p align="center">
  <img src="https://www.elastic.co/security-labs/grid.svg" />
</p>

## Betting on Bots: Investigating Linux malware, crypto mining, and gambling API abuse

Potential XMRIG Execution

The following EQL query can be used to hunt for XMRIG executions within your environment.

```sql
process where event.type == "start" and event.action == "exec" and (
  (
    process.args in ("-a", "--algo") and process.args in (
      "gr", "rx/graft", "cn/upx2", "argon2/chukwav2", "cn/ccx", "kawpow", "rx/keva", "cn-pico/tlo", "rx/sfx", "rx/arq",
      "rx/0", "argon2/chukwa", "argon2/ninja", "rx/wow", "cn/fast", "cn/rwz", "cn/zls", "cn/double", "cn/r", "cn-pico",
      "cn/half", "cn/2", "cn/xao", "cn/rto", "cn-heavy/tube", "cn-heavy/xhv", "cn-heavy/0", "cn/1", "cn-lite/1",
      "cn-lite/0", "cn/0"
    )
  ) or
  (
    process.args == "--coin" and process.args in ("monero", "arqma", "dero")
  )
) and process.args in ("-o", "--url")
```

##

MSR Write Access Enabled

XMRIG leverages modprobe to enable write access to MSR. This activity is abnormal, and should not occur by-default.

```sql
process where event.type == "start" and event.action == "exec" and process.name == "modprobe" and
process.args == "msr" and process.args == "allow_writes=on"
```

##

Potential GSOCKET Activity

This activity is default behavior when deploying GSOCKET through the recommended deployment methods. Additionally, several arguments are added to the query to decrease the chances of missing a more customized intrusion through GSOCKET.

```sql
process where event.type == "start" and event.action == "exec" and
process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
process.command_line : (
"*GS_ARGS=*", "*gs-netcat*", "*gs-sftp*", "*gs-mount*", "*gs-full-pipe*", "*GS_NOINST=*", "*GSOCKET_ARGS=*", "*GS_DSTDIR=*", "*GS_URL_BASE=*", "*GS_OSARCH=*", "*GS_DEBUG=*", "*GS_HIDDEN_NAME=*", "*GS_HOST=*", "*GS_PORT=*", "*GS_TG_TOKEN=*", "*GS_TG_CHATID=*", "*GS_DISCORD_KEY=*", "*GS_WEBHOOK_KEY=*"
)
```

##

Potential Process Masquerading via Exec

GSOCKET leverages the exec -a method to run a process under a different name. GSOCKET specifically leverages masquerades as kernel processes, but other malware may masquerade differently.

```sql
process where event.type == "start" and event.action == "exec" and
process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and process.args == "-c" and process.command_line : "* exec -a *"
```

##

Renice or Ulimit Execution

Several malwares, including KAIJI and RUDEDEVIL, leverage the renice utility to change the priority of processes or set resource limits for processes. This is commonly used by miner malware to increase the priority of mining processes to maximize the mining performance.

```sql
process where event.type == "start" and event.action == "exec" and (
  process.name in ("ulimit", "renice") or (
  process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and process.args == "-c" and
  process.command_line : ("*ulimit*", "*renice*")
  )
)
```

##

Inexistent Cron(d) Service Started

Both KAIJI and RUDEDEVIL establish persistence through the creation of a cron(d) service in /etc/init.d/cron(d). Cron, by default, does not use a SysV Init service. Execution of a cron(d) service is suspicious, and should be analyzed further.

```sql
process where event.type == "start" and event.action == "exec" and
  process.name == "systemctl" and process.args == "start" and process.args in
  ("cron.service", "crond.service", "cron", "crond")
```

##

Suspicious /etc/ Process Execution from KAIJI

The /etc/ directory is not a commonly used directory for process executions. KAIJI is known to place a binary called 32678 and id.services.conf in the /etc/ directory, to establish persistence and evade detection.

```sql
process where event.type == "start" and event.action == "exec" and (process.executable regex """/etc/[0-9].*""" or process.executable : ("/etc/*.conf", "/etc/.*"))
```

##

Hidden File Creation in /dev/ directory

Creating hidden files in /dev/ and /dev/shm/ are not inherently malicious, however, this activity should be uncommon. KAIJI, GSOCKET and other malwares such as K4SPREADER are known to drop hidden files in these locations.

```sql
file where event.type == "creation" and file.path : ("/dev/shm/.*", "/dev/.*")
```

##

Suspicious Process Execution from Parent Executable in /boot/

Malwares such as KAIJI and XORDDOS are known to place executable files in the /boot/ directory, and leverage these to establish persistence while attempting to evade detection.

```sql
process where event.type == "start" and event.action == "exec" and process.parent.executable : "/boot/*"
```