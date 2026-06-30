# AttkFinder

_AttkFinder_ is a tool that performs static program analysis of PLC programs, and 
produce _Data-oriented Attack_ vectors. In a nutshell, _AttkFinder_ takes PLC programs written 
under the standard [IEC-61131-3](https://webstore.iec.ch/publication/4552) in xml-format or structured text, 
and builds a Data-Flow graph (DFG), a Control-Flow graph (CFG) and translates the program 
into a Structured Intermediate Representation Language (STIR) version. A symbolic 
execution engine analyses the stir-version code searching for attack vectors that can be 
exploited by a malicious actuator.

The article 
"_AttkFinder: Discovering Attack Vectors in PLC Programs using Information Flow Analysis_" 
describes how _AttkFinder_ seeks suitable attack vectors in 
Cyber-Physical systems.

The tool is mainly written in Python3. A [neo4j](https://neo4j.com/) DB stores 
the Data-Flow and Control-Flow graphs. The Z3 library powers the symbolic execution 
engine that evaluates and produces the attack vectors.


## Libraries
* neomodel
* py2neo
* z3


## Configure Graph DB access
```
export NEO4J_USERNAME="<USER>"
export NEO4J_PASSWORD="<PASSWORD>"
export NEO4J_BOLT_URL="bolt://$NEO4J_USERNAME:$NEO4J_PASSWORD@localhost:7687"
```

## Usage

`./xml_parser.py -i <source_file/dir> -f <xml/st>`

