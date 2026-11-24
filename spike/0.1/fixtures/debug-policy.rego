package policy

import future.keywords.every
import future.keywords.in

api_version := "0.11.0"
framework_version := "0.2.3"

fragments := [
  {
    "feed": "mcr.microsoft.com/aci/aci-cc-infra-fragment",
    "includes": [
      "containers",
      "fragments"
    ],
    "issuer": "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.3",
    "minimum_svn": "4"
  }
]

containers := [{"allow_elevated":false,"allow_stdio_access":true,"capabilities":{"ambient":[],"bounding":["CAP_AUDIT_WRITE","CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_FSETID","CAP_KILL","CAP_MKNOD","CAP_NET_BIND_SERVICE","CAP_NET_RAW","CAP_SETFCAP","CAP_SETGID","CAP_SETPCAP","CAP_SETUID","CAP_SYS_CHROOT"],"effective":["CAP_AUDIT_WRITE","CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_FSETID","CAP_KILL","CAP_MKNOD","CAP_NET_BIND_SERVICE","CAP_NET_RAW","CAP_SETFCAP","CAP_SETGID","CAP_SETPCAP","CAP_SETUID","CAP_SYS_CHROOT"],"inheritable":[],"permitted":["CAP_AUDIT_WRITE","CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_FSETID","CAP_KILL","CAP_MKNOD","CAP_NET_BIND_SERVICE","CAP_NET_RAW","CAP_SETFCAP","CAP_SETGID","CAP_SETPCAP","CAP_SETUID","CAP_SYS_CHROOT"]},"command":["/skr.sh"],"env_rules":[{"pattern":"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","required":false,"strategy":"string"},{"pattern":"BUILD_DIR=/go/src/github.com/microsoft/confidential-sidecar-containers","required":false,"strategy":"string"},{"pattern":"TERM=xterm","required":false,"strategy":"string"},{"pattern":"(?i)(FABRIC)_.+=.+","required":false,"strategy":"re2"},{"pattern":"HOSTNAME=.+","required":false,"strategy":"re2"},{"pattern":"T(E)?MP=.+","required":false,"strategy":"re2"},{"pattern":"FabricPackageFileName=.+","required":false,"strategy":"re2"},{"pattern":"HostedServiceName=.+","required":false,"strategy":"re2"},{"pattern":"IDENTITY_API_VERSION=.+","required":false,"strategy":"re2"},{"pattern":"IDENTITY_HEADER=.+","required":false,"strategy":"re2"},{"pattern":"IDENTITY_SERVER_THUMBPRINT=.+","required":false,"strategy":"re2"},{"pattern":"azurecontainerinstance_restarted_by=.+","required":false,"strategy":"re2"}],"exec_processes":[{"command":["/bin/sh"],"signals":[]},{"command":["/bin/bash"],"signals":[]}],"id":"mcr.microsoft.com/aci/skr:2.12","layers":["335710fca9480be919670dc57ef086019417ca61b4ab6e414ec6564dbf44aba8","c9b8c6aedca4caf903228a9f7394ebc4bf12b5d15d28b1a0e47960c776cc30a0","4b67070364eb1b13a866bf03d82328bd63e3bea26c248962b2088ab1a509c701","b5ee6d35e21278d78cb5cdda5b6c8ee8494bae6509ba4001362988b704df4e17","f5935ad47ced2fa7afb356ed328a953455a03379f43ada55d06cf67be61b2848","8b4842f06982817534a75bcf71865213b09dfa8313229c384e5201dadbd75e25"],"mounts":[{"destination":"/etc/resolv.conf","options":["rbind","rshared","rw"],"source":"sandbox:///tmp/atlas/resolvconf/.+","type":"bind"}],"name":"skr-sidecar-container","no_new_privileges":false,"seccomp_profile_sha256":"","signals":[9,15],"user":{"group_idnames":[{"pattern":"","strategy":"any"}],"umask":"0022","user_idname":{"pattern":"","strategy":"any"}},"working_dir":"/"},{"allow_elevated":false,"allow_stdio_access":true,"capabilities":{"ambient":[],"bounding":["CAP_AUDIT_WRITE","CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_FSETID","CAP_KILL","CAP_MKNOD","CAP_NET_BIND_SERVICE","CAP_NET_RAW","CAP_SETFCAP","CAP_SETGID","CAP_SETPCAP","CAP_SETUID","CAP_SYS_CHROOT"],"effective":["CAP_AUDIT_WRITE","CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_FSETID","CAP_KILL","CAP_MKNOD","CAP_NET_BIND_SERVICE","CAP_NET_RAW","CAP_SETFCAP","CAP_SETGID","CAP_SETPCAP","CAP_SETUID","CAP_SYS_CHROOT"],"inheritable":[],"permitted":["CAP_AUDIT_WRITE","CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FOWNER","CAP_FSETID","CAP_KILL","CAP_MKNOD","CAP_NET_BIND_SERVICE","CAP_NET_RAW","CAP_SETFCAP","CAP_SETGID","CAP_SETPCAP","CAP_SETUID","CAP_SYS_CHROOT"]},"command":["/tests/skr/attest_client.sh"],"env_rules":[{"pattern":"AttestClientMAAEndpoint=sharedeus.eus.attest.azure.net","required":false,"strategy":"string"},{"pattern":"AttestClientRuntimeData=eyJrZXlzIjpbeyJlIjoiQVFBQiIsImtleV9vcHMiOlsiZW5jcnlwdCJdLCJraWQiOiJOdmhmdXEyY0NJT0FCOFhSNFhpOVByME5QXzlDZU16V1FHdFdfSEFMel93Iiwia3R5IjoiUlNBIiwibiI6InY5NjVTUm15cDh6Ykc1ZU5GdURDbW1pU2VhSHB1akcyYkNfa2VMU3V6dkRNTE8xV3lyVUp2ZWFhNWJ6TW9PMHBBNDZwWGttYnFIaXNvelZ6cGlORExDbzZkM3o0VHJHTWVGUGYyQVBJTXUtUlNyek41NnF2SFZ5SXI1Y2FXZkhXay1GTVJEd0FlZnlOWVJIa2RZWWtnbUZLNDRoaFVkdGxDQUtFdjVVUXBGWmp2aDRpSTlqVkJkR1lNeUJhS1FMaGpJNVdJaC1RRzZaYTVzU3VPQ0ZNbm11eXV2TjVEZmxwTEZ6NTk1U3MtRW9CSVktTmlsNmxDdHZjR2dSLUlialVZSEFPczVhamFtVHpnZU84a3gzVkNFOUhjeUtteVVac2l5aUY2SURScDJCcHkzTkhUakl6N3Rta3BUSHg3dEhuUnRsZkUyRlV2MEI2aV9RWWxfWkE1USJ9XX0=","required":false,"strategy":"string"},{"pattern":"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","required":false,"strategy":"string"},{"pattern":"BUILD_DIR=/go/src/github.com/microsoft/confidential-sidecar-containers","required":false,"strategy":"string"},{"pattern":"TERM=xterm","required":false,"strategy":"string"},{"pattern":"(?i)(FABRIC)_.+=.+","required":false,"strategy":"re2"},{"pattern":"HOSTNAME=.+","required":false,"strategy":"re2"},{"pattern":"T(E)?MP=.+","required":false,"strategy":"re2"},{"pattern":"FabricPackageFileName=.+","required":false,"strategy":"re2"},{"pattern":"HostedServiceName=.+","required":false,"strategy":"re2"},{"pattern":"IDENTITY_API_VERSION=.+","required":false,"strategy":"re2"},{"pattern":"IDENTITY_HEADER=.+","required":false,"strategy":"re2"},{"pattern":"IDENTITY_SERVER_THUMBPRINT=.+","required":false,"strategy":"re2"},{"pattern":"azurecontainerinstance_restarted_by=.+","required":false,"strategy":"re2"}],"exec_processes":[{"command":["/bin/sh"],"signals":[]},{"command":["/bin/bash"],"signals":[]}],"id":"mcr.microsoft.com/aci/skr:2.12","layers":["335710fca9480be919670dc57ef086019417ca61b4ab6e414ec6564dbf44aba8","c9b8c6aedca4caf903228a9f7394ebc4bf12b5d15d28b1a0e47960c776cc30a0","4b67070364eb1b13a866bf03d82328bd63e3bea26c248962b2088ab1a509c701","b5ee6d35e21278d78cb5cdda5b6c8ee8494bae6509ba4001362988b704df4e17","f5935ad47ced2fa7afb356ed328a953455a03379f43ada55d06cf67be61b2848","8b4842f06982817534a75bcf71865213b09dfa8313229c384e5201dadbd75e25"],"mounts":[{"destination":"/etc/resolv.conf","options":["rbind","rshared","rw"],"source":"sandbox:///tmp/atlas/resolvconf/.+","type":"bind"}],"name":"test-attest-maa-client-container","no_new_privileges":false,"seccomp_profile_sha256":"","signals":[9,15],"user":{"group_idnames":[{"pattern":"","strategy":"any"}],"umask":"0022","user_idname":{"pattern":"","strategy":"any"}},"working_dir":"/"},{"allow_elevated":false,"allow_stdio_access":true,"capabilities":{"ambient":[],"bounding":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],"effective":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],"inheritable":[],"permitted":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"]},"command":["/pause"],"env_rules":[{"pattern":"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","required":true,"strategy":"string"},{"pattern":"TERM=xterm","required":false,"strategy":"string"}],"exec_processes":[],"layers":["16b514057a06ad665f92c02863aca074fd5976c755d26bff16365299169e8415"],"mounts":[],"name":"pause-container","no_new_privileges":false,"seccomp_profile_sha256":"","signals":[9,15],"user":{"group_idnames":[{"pattern":"","strategy":"any"}],"umask":"0022","user_idname":{"pattern":"","strategy":"any"}},"working_dir":"/"}]

allow_properties_access := true
allow_dump_stacks := true
allow_runtime_logging := true
allow_environment_variable_dropping := true
allow_unencrypted_scratch := false
allow_capability_dropping := true

mount_device := data.framework.mount_device
unmount_device := data.framework.unmount_device
mount_overlay := data.framework.mount_overlay
unmount_overlay := data.framework.unmount_overlay
create_container := data.framework.create_container
exec_in_container := data.framework.exec_in_container
exec_external := data.framework.exec_external
shutdown_container := data.framework.shutdown_container
signal_container_process := data.framework.signal_container_process
plan9_mount := data.framework.plan9_mount
plan9_unmount := data.framework.plan9_unmount
get_properties := data.framework.get_properties
dump_stacks := data.framework.dump_stacks
runtime_logging := data.framework.runtime_logging
load_fragment := data.framework.load_fragment
scratch_mount := data.framework.scratch_mount
scratch_unmount := data.framework.scratch_unmount
rw_mount_device := data.framework.rw_mount_device

reason := {"errors": data.framework.errors}