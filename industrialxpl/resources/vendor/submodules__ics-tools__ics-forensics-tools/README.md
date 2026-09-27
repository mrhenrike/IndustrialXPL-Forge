<img src='https://github.com/microsoft/ics-forensics-tools/blob/main/assets/img/section52.png' img align='right' width='377' height='100'/>
<br/>

# [Microsoft Section52 ICS Forensics tools](https://azure.microsoft.com/en-us/products/iot-defender/)

## INTRODUCTION
Microsoft Section52 ICS Forensics Tools is an open source forensic toolkit for analyzing
Industrial PLC metadata and project files. Microsoft Section52 ICS Forensics Tools enables
investigators to identify suspicious artifacts on ICS environment for detection of compromised devices
during incident response or manual check. Microsoft Section52 ICS Forensics Tools is
open source, which allows investigators to verify the actions of
the tool or customize it to specific needs, currently support Siemens S7 via Snap7.

## SUPPORTED SCENARIOS
- OB usage
- Block author
- Offline - Online comparison
- Call Graphs
- Timestamps outliers
- Network usage

## Executing and arguments

This tool requires Python 3.8 or later.

### Install required Python packages
`pip install -r requirements.txt`

### The arguments:
 **args**  | **Description**							                                      | **Must / Optional**
-----------| ------------------------------------------------------------------------------| -------------------
`-h`, `--help`							|show this help message and exit						| ----
`-so`, `--stdout_output`				|Print output to stdout									|optional
`-fo`, `--file_output`					|Store output in file									|optional
`-v`, `--verbose`						|Verbose logging											| optional
`-if`, `--ip_addresses_file`			|IP addresses file to scan								|optional
`-sc`, `--scan`							|Scan for Siemens S7 PLCs in network segment (x.y.z.)	|optional
`-ov`, `--override_output_dirs`			|Override output directories								|optional , default - True
`-pn`, `--port_number`					|Port number for connecting or scanning					|optional, default - 102
`-co`, `--compare_online_vs_offline`	|Compare between online and offline projects				|optional
`-ci`, `--compare_ip`					|PLC IP with online blocks to compare					|optional
`-opd`, `--offline_projects_directory`	|Offline projects directory |optional
`-opdn`, `--offline_project_dir_name`	|Offline project directory name	|optional
`-la`, `--logic_all`					|Execute all logic options	|optional
`-lau`, `--logic_author`				|Execute author logic |optional
`-ld`, `--logic_dates`					|Execute dates logic |optional
`-ln`, `--logic_network`				|Execute network logic|optional
`-lo`, `--logic_ob`						|Execute organizational blocks logic|optional


### Executing examples:
	 ./main.py -i 192.168.88.1 -la
	 ./main.py -i 192.168.88.1 -pn 220 -la
	 ./main.py -ci 192.168.88.1 -co -opd '\s7_proj' -opdn '\s7_proj'


### Output:
Depending on the model you choose to investigate, the data presented per model
- Upload project from PLC and parsing status
- Author block names and uniqueness -
    <br/>   
    <img src='https://github.com/microsoft/ics-forensics-tools/blob/main/assets/img/author_block_metadata.png' img align='center'/>
    <br/><br/>
- Timestamp Outliers Anomalies
    <br/>    
    <img src='https://github.com/microsoft/ics-forensics-tools/blob/main/assets/img/time_outliers.png' img align='center'/>
    <br/><br/>
  
- Network Logic
    <br/>    
    <img src='https://github.com/microsoft/ics-forensics-tools/blob/main/assets/img/communication.png' img align='center'/>
    <br/><br/>
  
- Call graph - program connection base execution graph
    <br/>    
    <img src='https://github.com/microsoft/ics-forensics-tools/blob/main/assets/img/graph_exmp.png' img align='center'/>
    <br/>
<br/>
- OB metadata
    <br/><br/>
        <img src='https://github.com/microsoft/ics-forensics-tools/blob/main/assets/img/ob_usage.png' img align='center'/>
    <br/>
<br/>
- Online <-> Offline Block Comparison
    <br/><br/>
        <img src='https://github.com/microsoft/ics-forensics-tools/blob/main/assets/img/offline_online_compare.png' img align='center' width='370' height='300'/>
    <br/>
<br/>

## Resources and Technical data & solution:
[Microsoft Defender for IoT](https://azure.microsoft.com/en-us/services/iot-defender/#overview) is an agentless network-layer security solution that allows
organizations to continuously monitor and discover assets, detect threats, and manage vulnerabilities in their IoT/OT
and Industrial Control Systems (ICS) devices, on-premises and in Azure-connected environments.

[Section 52 under MSRC blog](https://msrc-blog.microsoft.com/?s=section+52)    <br/>
[ICS Lecture given about the tool](https://ics2022.sched.com/event/15DB2/deep-dive-into-plc-ladder-logic-forensics)    <br/>
[Section 52 - Investigating Malicious Ladder Logic | Microsoft Defender for IoT Webinar - YouTube](https://www.youtube.com/watch?v=g3KLq_IHId4&ab_channel=MicrosoftSecurityCommunity)

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.

## Legal Disclaimer

Copyright (c) 2018 Microsoft Corporation. All rights reserved.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.










