# CUBE-MALIOT-2021

The Internet-of-Things (IoT) has enabled a wide range of new applications in modern-day application domains, including healthcare, transportation and agriculture. Unfortunately, attackers also increasingly target IoT devices with malware, including infamous malware families such as Mirai, Gafgyt, and Tsunami. In response, numerous malware analysis and detection methods have been proposed in the literature. However, authors of existing papers collected separate malware data sets for evaluating their methods, making it hard for the community to reproduce and compare their results.

We publish our data set, called "CrySyS-Ukatemi BEnchmark: MALware for IOT devices 2021", or CUBE-MALIOT-2021 for short, with the aim of alleviating this issue by providing the community with a publicly available set of IoT malware samples for benchmarking existing and future IoT malware analysis and detection methods. In contrast to most other publicly available malware data sets, CUBE-MALIOT-2021 does not contain only features extracted from malware samples, but it also contains the raw binary executable files of the samples. While some available data sets do contain malware binaries, those are typically Windows PE files, which are not so characteristic to the IoT domain. In contrast, the malware binaries in the CUBE-MALIOT-2021 data set are all ELF executable files, compiled for the ARM or MIPS platform, targeting embedded IoT devices. Besides the binaries, the data set also contains metadata of the malware samples obtained from the binary files themselves and from their VirusTotal analysis reports.

To the best of our knowledge, such a large data set containing raw binaries of IoT malware is not yet publicly available to the research community (as of November 2021). By being the first of its kind, we hope that the CUBE-MALIOT-2021 data set will become a de facto benchmark data set in the research areas of IoT malware detection and IoT malware analysis in order to satisfy the need for the comparability and reproducibility of research results.

## Description of the data set

The CUBE-MALIOT-2021 data set consists of 29,209 ELF binaries compiled for the ARM platform and 18,715 ELF binaries compiled for the MIPS platform. Based on information in their headers, all ARM samples were compiled for the 32-bit architecture, and 18,603 MIPS samples were compiled for the 32-bit architecture and 112 samples target the 64-bit architecture. All samples are executable files.

The file sizes in the data set range from a few bytes up to 250 KB, with the majority of the files having 50-150 KB file sizes. Based on their binary entropy analysis, we found that the majority of the samples in data set are not packed or encrypted; however, there are some samples with a large entropy value. Based on the ELF header fields, of the ARM samples, 15,889 samples are stripped, 13,316 are not stripped, and for 4 samples, this information is unknown. Of the MIPS samples, 12,298 samples are stripped, 6,409 samples are not stripped, and no information is available for 8 samples. With respect to linking, of the ARM samples in the data set, 26,515 samples are statically linked, 2,678 samples are dynamically linked, and for 17 samples, the linking information states "static (uses shared libs)". Of the MIPS samples, 18,627 samples are statically linked and 88 are dynamically linked.

All metadata of the raw binaries is available as JSON documents, where the file name of each JSON document is the SHA256 hash of the corresponding malicious binary. These JSON documents contain information obtained from the binaries (e.g., ELF header information, file size, etc.) and information obtained from the VirusTotal analysis reports of the samples (e.g., first submission date to VirusTotal, antivirus labels assigned by antivirus products, etc.). As for the first submission date, the data set contains samples that were submitted to VirusTotal not later than September 2019. Accurate antivirus labels were computed with a slightly modified version of AVClass (version 1).

## Content of this repository

In this repository, one can find the metadata of the CUBE-MALIOT-2021 data set:

- The file `cube-maliot-json.schema` contains the JSON schema that describes the structure of the metadata files.
- The folders `arm` and `mips` hold the JSON files containing the metadata of malicious binaries for the corresponding platform.
- The  folder `avclass_config` contains the malware family label aliases and the generic tokens that we used to configure AVClass when computing the labels for the samples in the data set.

## How to get the malware sample binaries?

The raw binaries of the malware samples can be downloaded from [here](https://cloud.crysys.hu/s/WMKgGqxZsaQPPgf)
in a password-protected archive.

Parties interested in getting access to the binaries must request the password by filling in a form of declaration and submitting it to `cube-maliot@crysys.hu`. The declaration form can be found in this repository, in the folder `declaration_form`.

By filling, signing, and submitting the form, interested parties declare that they will use the data set only for research or educational purposes and take precautions when working with the malware samples in order to avoid causing any (intentional and unintentional) harm. After processing the submitted form, the password will be sent back via e-mail. We may change the password periodically, so interested parties should keep their own copy of the archive containing the malware sample binaries in order to preserve continous access to them.

We handle data provided in the submitted declaration forms as specified in our privacy policy available in the folder `privacy_policy`.

## Giving credit

Parties who use our data set should refer to it as the `CUBE-MALIOT-2021` data set in any published work that relies on it or on any part of it, providing also, if possible, the URL `https://github.com/CrySyS/cube-maliot-2021` of this repository.

## Ethical statement

We understand that, by publishing the raw binaries of real-world malware samples, we create the risk of misusing them for potentially malicious purposes, and we take the following precautions to minimize this risk:

- We deliberately included only aged malware samples in our data set, which are already known to mainstream anti-virus products, hence, detectable in computer systems that employ state-of-the-art malware protection measures. More specifically, even the latest malware sample in our data set is more than two years old.
- We control access to the malware samples in the data set by including them in a password-protected archive and making the password available to interested parties via a controlled procedure described above, whereby we request them to explicitly declare that (1) they understand the risks of working with executable malware and they take precautions to avoid causing any (intentional and unintentional) harm to any operating computer systems ever; (2) they use the samples exclusively for research or educational purposes, and specifically, they do not use the samples and any parts of the samples with malicious intent ever; (3) they do not distribute the samples and any parts of the samples to third parties, and they make precautions to avoid unauthorized access to the samples in or leakage of the samples from their infrastructure.
- We make a reasonable effort to verify the identity of any interested party that submits a request for the password and the above declaration to us.
- We periodically change the password, and we use strong passwords.

## Acknowledgement

The CUBE-MALIOT-2021 data set was compiled as part of the [SETIT Project](https://www.crysys.hu/research/setit/) (2018-1.2.1-NKP-2018-00004), which has been implemented with the support provided from the National Research, Development and Innovation Fund of Hungary, financed under the 2018-1.2.1-NKP funding scheme.

Our work was also supported by the Ministry of Innovation and Technology NRDI Office, Hungary, within the framework of the Artificial Intelligence National Laboratory Program.

The authors are thankful to [VirusTotal](https://www.virustotal.com/) for giving the permission to use data from VirusTotal analysis reports in the construction of the CUBE-MALIOT-2021 data set.

## Conact information

Any comments, questions, and request should be sent to `cube-maliot@crysys.hu` written in English.
