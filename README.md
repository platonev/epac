# An Encryption and Probability based Access Control Model for Named Data Networking

the goal of **epac** to implement [An Encryption and Probability based Access Control Model for Named Data Networking](http://ieeexplore.ieee.org/abstract/document/7017100/)
# ndnpeek and ndnpoke

**epacconsumer** and **epacprovider** are a pair of programs to request and make available for retrieval of a single Data packet.

* **epacconsumer** is a consumer program that sends one Interest and expects one Data.
* **epacprovider** is a producer program that serves one Data in response to an Interest.

Usage example:

1. start NFD on local machine
2. execute `echo 'HELLO WORLD' | epacprovider ndn:/localhost/demo/hello`
3. on another console, execute `epacconsumer -p ndn:/localhost/demo/hello`
