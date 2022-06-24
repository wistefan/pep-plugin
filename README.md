# Kong PEP-Plugin

Plugin for [Kong](https://konghq.com/) to support the usage of Kong as a [PEP-Proxy](https://github.com/FIWARE/tutorials.PEP-Proxy). The current implementation supports the usage of [Keyrock](https://github.com/ging/fiware-idm) as descion point.

## Configuration

| Key| Description | Default |Required|Allowed values|
|----|-------------|---------|--------|--------------|
|authorizationendpointtype| Type of the desicion point. | ```nil```| ```true```| ```Keyrock``` |
|authorizationendpointaddress| Url to be contacted for authorization. F.e. https://keyrock.dev/users | ```nil```| ```true```| type.URL |   
|keyrockappid| Id of the app in Keyrock that should be checked. | ```nil```| ```true``` in case of type ``Keyrock```| type.String |
|decisioncacheexpiryins| How fast should the desicion cache expire? Caching is disabled if set to -1 | ```60``` | ```false``` | type.Int64|   