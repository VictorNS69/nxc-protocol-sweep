# nxc-protocol-sweep
Multi-protocol scanner using nxc (NetExec)

## Requirements
- NetExec: <https://www.netexec.wiki/getting-started/installation>
- Python 3.0

## Usage
```bash
python3 nxc-sweep.py [-h] -u USERNAME -p PASSWORD [-d] ip
```

## Examples
- Valid credentials:

![Valid protocols](https://github.com/VictorNS69/nxc-protocol-sweep/blob/main/images/valid-protocols.png)
- Invalid credentials

![Invalid protocols](https://github.com/VictorNS69/nxc-protocol-sweep/blob/main/images/invalid-protocols.png)

## Optional instalation
1. Move to OPT directory: `cd /opt`
2. Clone the repository: `git clone git@github.com:VictorNS69/nxc-protocol-sweep.git`
3. Move to the cloned repository: `cd nxc-protocol-sweep`
4. Give execution rights to the script: `chmod +x nxc-sweep.py`
5. Create symbolic link: `sudo ln -s /opt/nxc-protocol-sweep/nxc-sweep.py /usr/bin/nxc-sweep`
6. Test the tool: `nxc-sweep`
