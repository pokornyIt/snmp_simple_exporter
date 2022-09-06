# SNMP Simple Exporter

Simple SNMP exporter for Prometheus.
The project is inspired [snmp-prom](https://github.com/pschou/snmp-prom) project.

# Motivation

To monitor devices with SNMP service, I used the official [snmp_exporter](https://github.com/prometheus/snmp_exporter). 
This exporter is complex to configure. Its disadvantage is the necessity to minimize the inputs if I do not
need all the information from the tree.

The alternative in the snmp-prom exporter is very suitable for collecting only targeted data. Considering the use of the
exporter on a system where Docker services will not be supported, I added binary applications to the project and
modified the code as well.
