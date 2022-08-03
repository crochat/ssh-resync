# ssh-resync
Automatic ssh keys resynchronization

After a wide infrastructure rebuilt, when many servers changed, but still keeping the same IP address, all the SSH keys in the different *known_hosts* files are deprecated. The goal here is to take a list of hosts which potentially have keys conflicts, clean the *known_hosts* files from these hosts, and refresh the matching keys. This has to be done for all users on the machine at once.
