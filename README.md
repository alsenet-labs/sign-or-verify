# sign-or-verify

## LICENSE
 Copyright (c) 2018 ALSENET SA

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.

## Documentation

NodeJS / browser

```
  var signOrVerify=require('sign-or-verify').signOrVerify;
  signOrVerify(options /* see source code */)
  .then(function(result){
    ...
  })
  .catch(console.error);

```

Command line
```

  Usage: sign-or-verify [options] [command]

  Options:

    -V, --version          output the version number
    -T, --list-hash-types  
    -A, --list-algorithms  
    -D, --debug            
    -h, --help             output usage information

  Commands:

    sign [options]         Compute a signature
    verify [options]       Verify a signature

  Usage: sign [options]

  Compute a signature

  Options:

    -p, --pem <filename|string>  private key in pkcs8 format
    -t, --hash-type <type>       
    -a, --algorithm <type>       
    -i, --input <file>           file to process
    -h, --help                   output usage information

  Usage: verify [options]

  Verify a signature

  Options:

    -p, --pem <filename|string|url>  public key in pkcs8 format or https url (to use website x509 certificate)
    -t, --hash-type <type>           
    -a, --algorithm <type>           
    -s, --signature <file>           signature to verify
    -i, --input <file>               file to process
    -h, --help                       output usage information
```
