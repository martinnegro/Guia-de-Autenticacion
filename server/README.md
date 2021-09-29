# Guía de Autenticación con Passport JS

Basado en [Autenticación de usuario en aplicaciones web (Passport.js, Node, Express)](https://www.youtube.com/watch?v=F-sFp_AvHc8)

En esta guía es para implementar Autenticación de Usuarios desde el lado del servidor con Json Web Token (JWT de ahora en más) utilizando la librería Passport. 

Está dirigida a estudiantes de Desarrollo Web y es aplicable a prototipos y modelos de negocios pequeños, ya que vamos a proveer a nuestras aplicaciones de un sistema de autenticación suficientemente seguro.

Tiene como objetivo definir un paso a paso práctico de implementación a su vez de tratar de entender el funcionamiento concreto de la autenticación con JWT

Se deben tener conocimientos previos sobre Node, Express (y el funcionamiento de middlewares), Sequelize y Postgres, aunque es aplicable a cualquier ORM y Base de Datos.

#### Antes de comenzar:
- En este texto no se explica de que manera conectar el servidor a la base de datos, ni como configurar las tablas. Si necesitas reforzar estos conceptos, es recomendable buscar fuentes que lo expliquen y luego retomar esta guía.
- Se usarán conceptos de criptografía, pero no se proveerá de una explicación profunda porque excede el objetivo. Sí se abordarán conceptos generales para entender cómo aplicar la tecnología en nuestra autenticación y porqué es importante.
- La implementación del front es indistinta, puede ser React, Angular o cualquier otro framework. Lo importante a tener en cuenta es que vamos a estar haciendo peticiones POST en cuyo body se encontrarán los datos necesarios (email y password).

## Creando passwords

Para poder autenticar un usuario, primero hay que crearlo y guardar bien la contraseña.
A modo de ejemplo, tomemos la siguiente solicitud POST:
``` http
POST http://localhost:3002/signup
Content-Type: application/json

{
    "email": "martin@email.com",
    "password": "Password_S3gura"
}
```
Sabemos que nuestro servidor recibirá esos datos dentro de su body por lo que configuramos nuestra app:
```
DIRECTORIO
└── server
    ├── db
    ├── index.js
    ├── app.js
    └── routes
        └── index.js
```


``` js 
// server/app.js

const express = require('express');
const app = express();
const morgan = require('morgan')

/********* MIDDLEWAREs ******/
app.use(morgan('dev'));
app.use(express.json());

/********* RUTAS *************/
app.use('/',require('./routes'))

module.exports = app;
```

```js
// server/routes/index.js
const { Router } = require('express');
const router = Router();

router.post('/signup', (req, res, next) => {
    const { email, password } = req.body;
    res.json({ message: `Recibido email: ${email}` })
});

module.exports = router;
```

En este punto, si ejecutaramos `app/index.js` y realizaramos la solicitud que definimos al comenzar, obtendríamos de respuesta un json: `{ message: 'Recibido email: martin@email.com }`.

Ahora configuremos dentro de la ruta `/signup` el código para guardar nuestro nuevo usuario y su contraseña. Es este ejemplo se usa Sequelize y Postgres para guardar los datos, pero aplica igual para otros ORM y Bases de Datos.

```js
// server/routes/index.js

const { Router } = require('express');
const router = Router();

const { User } = require('../db');
const { genPassword } = require('./utils');

router.post('/signup', async (req, res) => {
    const { email, password } = req.body;

    try {
        const exists = await User.findOne({ where: { email } })
        if (exists) return res.status(401).send('El usuario ya existe')

        const { genHash, salt } = genPassword(password);
        
        const user = await User.create({
                    email,
                    hashed_password: genHash,
                    salt,
                })
        res.json({
            success: true,
            email: user.email
        })

    } catch(err) { res.sendStatus(500) };
});

module.exports = router;

```

En el código de arriba, como nuevo tenemos la función genPassword que nos devuelve genHash y salt. Como regla general, nunca debes guardar la contraseña en texto plano, por lo que para evitar esto vamos a generar dos items:
- salt: Un valor aleatorio para evitar que dos usuarios con la misma password obtengan el mismo hash.
- hash: la combinación entre password y salt.
Estos dos datos son los que vamos a usar para verificar más adelante la identidad del usuario.

Definimos el siguiente directorio:
```
DIRECTORIO
└── server
    ├── db
    ├── index.js
    ├── app.js
    └── routes
        └── index.js
        └── utils.js
```
Y generamos nuestras funciones genPassword y validatePassword:
```js
// server/utils

const crypto = require('crypto')

const genPassword = (password) => {
    const salt = crypto.randomBytes(32).toString('hex');
    const genHash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
    return {
        salt,
        genHash
    }
};

const validatePassword = (password, hash, salt) => {
    const genHash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
    return hash === genHash;
};

module.exports = {
    genPassword,
    validatePassword
};
```

La librería crypto viene por defecto en Node y nos va a proveer de múltiples algoritmos de encriptación. En este caso se usa la configuración propuesta por la fuente (PBKDF2), pero es bueno saber que existen otras opciones y que están estandarizadas y documentadas. Se puede encontrar información [en el sitio de IETF](https://datatracker.ietf.org/doc/html/rfc8018#section-5.2) sobre el algoritmo elegido.

A modo informativo, el método `crypto.pbkdf2Sync()` (sync es función síncrona) toma los siguientes parámetros: password, salt, cantidad de iteraciones, la longitud del hash, y qué hash function se utiliza.

Estos métodos son deterministas, es decir al mismo input obtienen el mismo output de manera consistente, pero su seguridad radica en que No se puede obtener la password a partir del hash y que el hash posee un formato string hexadecimal que vamos a poder guardar en nuestra base de datos.

El siguiente paso es preparar la ruta `POST /signin`: 

```js
// server/routes

router.post('/signin', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ where: { email } });
        if (!user) return res.status(401).json({ message: 'El usuario no existe.' })

        const validation = validatePassword(password, user.hashed_password, user.salt)
        if (!validation) return res.status(401).json({ message: 'Password incorrecta.' })

        res.json({
            success: true,
            email: user.email
        })
    } catch(err) { res.sendStatus(500) }

});
```
En este punto deberíamos ser capaces de crear usuarios almacenando passwords de manera segura y poder verificar si el usuario que está intentado loguerse provee las credenciales correctas

Este método nos obliga a que debamos ingresar nuestros datos cada vez que querramos acceder a una ruta protegida, lo que causaría molestia en el usuario final y abandone nuestro sitio. Aquí es donde entran los JWT, que nos van permitir detectar si ya se ha realizado la autenticación y permitir acceder a rutas protegidas sin necesidad de reingresar credenciales.

## Public Key Cryptography

Antes de pasar a los tokens, primero vamos a tratar de entender como funcionan a través de teoría y su aplicación en código.

### Clave privada y clave pública

Podríamos generar tokens sin necesidad de usar un sistema de claves asímetrico, pero tener una clave privada y otra pública nos va a proveer de un método de autenticación robusto.

Un sistema asimétrico está compuesto por dos claves, una privada y otra pública, que __están matemáticamente relacionadas__. Aplicandolas en determinadas funciones tenemos dos usos principales:
- Encriptar datos: encriptando con pública y desencriptando con privada.
- Verificar identidades: encriptando con privada y desencriptando con pública.

Como indican sus nombres, estos usos son seguros siempre y cuando mantegamos en secreto la clave privada.

### Trap Door Function

Una función trap door es aquella que toma datos (por ej. en formato json) y los comprime de manera determinística devolviendo un hash de longitud fija, sin importar el tamaño de los datos originales. Igual que con las password, no se puede obtener la información original a partir del hash.

Un ejemplo de trap door function es Elliptic Curve Cryptography, que es la base de Public Key Cryptography. Esta función conecta matemáticamente la clave privada con la pública. Con ella podemos obtener la clave pública a partir de la privada, pero no podremos realizar el camino inverso.

### Creando par de claves

Ahora que ya conocemos las bases, podemos pasar al código con el que generaremos ambas claves. En una nueva carpeta creamos el siguiente archivo:

```js
// server/cryptography/genKeyPair.js

const crypto = require('crypto');
const fs = require('fs');

const genKeyPair = () => {
    const keyPair =  crypto.generateKeyPairSync('rsa',{ // Algoritmo rsa que genera el par
        modulusLength: 4096, // bits - el estándar para claves rsa
        publicKeyEncoding: {
            type: 'pkcs1', // Public Key Cryptography Standards 1
            format: 'pem'  // Formato de archivo más común
        },
        privateKeyEncoding: {
            type: 'pkcs1', // Public Key Cryptography Standards 1
            format: 'pem'  // Formato de archivo más común
        }
    });

    fs.writeFileSync(__dirname + '/id_rsa_pub.pem', keyPair.publicKey);
    fs.writeFileSync(__dirname + '/id_rsa_priv.pem', keyPair.privateKey);
};

genKeyPair();

```
Al ejecutar `node genKeyPair.js` obtendremos dos archivos con formato `.pem`, uno con la clave privada y otro con la pública. No está de más volver a aclarar que es importante mantener en secreto la clave privada, para así poder compartir la clave pública sin problemas y poder realizar autenticaciones de forma segura.

### Métodos de encriptación y desencriptación

Ahora que ya tenemos nuestras dos claves, generemos funciones de encriptación y desencriptación que utilicen estas claves, siguiendo la idea de los dos casos de uso mencionados anteriormente.

```js
// server/cryptography/encrypt.js
// MÉTODOS DE ENCRIPTACIÓN
const crypto = require('crypto');

const withPrivateKey = (privateKey, message) => {
    // Convierte el mensaje en Buffer para poder utilizarlo en el método de crypto
    const bufferMessage = Buffer.from(message,'utf8');
    return crypto.privateEncrypt(privateKey, bufferMessage)
};

const withPublicKey = (publicKey, data) => {
    const bufferData = Buffer.from(data,'utf8');
    return crypto.publicEncrypt(publicKey, bufferData);
};

module.exports = {
    withPublicKey,
    withPrivateKey
}

```
```js
// server/cryptography/decrypt.js}
// MÉTODOS DE DESENCRIPTACIÓN
const crypto = require('crypto');

const withPublicKey = (publicKey, encryptedData) => {
    return crypto.publicDecrypt(publicKey, encryptedData);
};

const withPrivateKey = (privateKey, encryptedData) => {
    return crypto.privateDecrypt(privateKey, encryptedData);
};

module.exports = {
    withPublicKey,
    withPrivateKey
}

```
En este caso definimos funciones para los dos tipos de uso, pero para entender los JWT solo vamos a usar los métodos para validar autenticaciones. Las otras funciones quedan a modo de ejemplo de como podríamos generar módulos para otros usos.

### Firma Digital

Lo importante de lo que viene ahora es entender el concepto de __firma digital__ que utilizan los JWT para validar identidades. Esto significa, en grandes rasgos, __combinar la información que estamos enviando con nuestra clave privada__ para generar un token que sea contrastable con la clave pública. 
Si el token que recibimos fue generado con una clave privada distinta a la que corresponde o los datos son distintos a los originales, quiere decir que la información ha sido manipulada y se rechazará la conexión.

Veamos como sería esto en código para firmar los datos. En este caso vamos a usar la clave privada con el método que escribimos anteriormente y a lo último exportamos la información necesaria para realizar la verificación. Ese objeto que exportamos es una *simulación* de un JWT. 

```js
// server/cryptography/signMessage.js

const crypto = require('crypto');
const fs = require('fs');
const encrypt = require('./encrypt');

// Ejemplo de datos de usuario que quisieramos transportar en nuestros tokens
const myData =  {
    email: 'martin@email.com',
    name: 'martin'
}

// Trap Door Function
const hash = crypto.createHash('sha256')
// Necesitamos nuestros datos en formato string para poder hashearlos
const myDataString = JSON.stringify(myData)
// Combinamos nuestra función hash con nuestros datos
hash.update(myDataString);
// Convertimos nuestros datos hasheados a formato hexadecimal
const hashedData = hash.digest('hex');

/****  Ahora pasamos a la FIRMA DIGITAL ****/
// Cargamos nuestra clave privada
const privateKey = fs.readFileSync(__dirname + '/id_rsa_priv.pem', 'utf8')

// Creamos un objeto Buffer con nuestro mensaje y la clave privada
// Es decir, firmamos nuestros datos
const signedData = encrypt.withPrivateKey(privateKey, hashedData) // Utilizamos el método que creamos anteriormente

// INFORMACIÓN ADICIONAL QUE ENVIAMOS PARA PODER VERIFICAR IDENTIDAD
// Este objeto sería la versión cruda de nuestro JWT
const packageOfData = {
    algorithm: 'sha256',
    originalData: myData,
    signedAndEncryptedData: signedData
}
// Exportamos el paquete de datos a modo de analogía 
// con el envío de JWT a través de internet
module.exports = {
    packageOfData
}
```
Como vemos arriba, no solo estamos encriptando los datos, sino que antes los pasamos por una función trap door que nos devuelve un hash, es decir, estamos agregando un paso más de seguridad a nuestros tokens.

Ahora necesitamos crear el código que verifica la información. En este caso, usamos la clave pública y buscamos corroborar que la información haya sido firmada con clave privada que corresponda a la pública
```js
// server/cryptography/verifyIdentity.js

const crypto = require('crypto');
const fs = require('fs');
const decrypt = require('./decrypt');

// Recibimos la información del módulo anterior
const receivedData = require('./signMessage').packageOfData;

// Cargamos nuestra clave pública.
const publicKey = fs.readFileSync(__dirname + '/id_rsa_pub.pem','utf8');

// Utilizamos el método decrypt que creamos anteriormente
// y le pasamos la clave pública y los datos firmados
const decryptedData = decrypt.withPublicKey(publicKey, receivedData.signedAndEncryptedData);
const decryptedDataHex =  decryptedData.toString();

// Aquí creamos un hash con el mismo algoritmo que nos enviaron.
const hash = crypto.createHash(receivedData.algorithm);

// Tomamos los datos originales sin hashear y los 
// pasamos por la trap door function con el algoritmo
// indicado dentro del paquete de información
const hashOfOriginal = hash.update(JSON.stringify(receivedData.originalData));
const hashOfOriginalHex = hash.digest('hex');

// Si los dos hash son idénticos se imprimirá true 
// y quiere decir que nuestra información es válida
console.log(hashOfOriginalHex === decryptedDataHex);
```
Si ejecutamos `node verifyIdentity.js` veriamos impreso en nuestra consola `true`, ya que los dos hash generados son idénticos. Si la información se corrompiera de alguna manera (por supuesto, mucho más probable enviando datos mediante internet que en este ejemplo de módulos) obtendríamos `false` indicando que no se ha firmado con la clave correcta o se manipularon los datos.

Es probable que los códigos anteriores no tengan una aplicación pŕactica real porque el envío a través de internet de los datos que necesitamos para realizar la autenticación es poco eficiente. Como se aclaró anteriormente, toda esta sección tiene como objetivo comprender más profundamente el funcionamiento de los JWT antes de pasar a la aplicación real. 

## Json Web Tokens

Los JWT son una forma de empaquetar toda esta información para que sea más fácil y eficiente de enviar a través de internet. 

Las especificaciones se encuentran [en el sitio de IETF](https://datatracker.ietf.org/doc/html/rfc7519) y [aquí cuentan con un debugger](https://jwt.io/) para ver su distintas estructuras.

### Estructura de un JWT

El siguiente snippet es un prototipo de JWT que nos permite ver su estructura general:
```
eyJhbGciOiJSUzI1NiIsInR5cGUiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.F4SZ0OyVkxsZvQS_Gw3AFKUz7VVKGhjfkKB0xIkymwLbNyUgSVVeBZFiAQyZQjUeuS-4gLPGwCJ4xj_HQsLsJllKejMlUg3oh0WnI0Z07FEqum4opVPNCMj1xKXMW3ioSxJfbMkSpJTeVZPdZgRCpp_LjKpg3sfdOl3_bnlsMILmRlqMuYsM9Qdm5-6v_WiJzGDMnLYs2WpyyXwqaPk7EoQWAU
```

Cada parte del token está codificada con base64url, un estándar de codificación que nos permite transportar información a través de internet minimizando la pérdida de datos.

Las distintas partes están divididas por un punto:
- La primera corresponde al algoritmo utilizado para la encriptación y el tipo de token, información necesaria para realizar la validación:
  ```
    {
        "alg": "HS256",
        "typ": "JWT"
    }
  ```
- La segunda es el payload que contiene datos sobre algún tipo de entidad. Además puede contener otros *claims* estandarizados que nos indiquen información sobre el token como `iat`(Issued At), `exp`(Expiration Times), entre otros. No se debe poner información sensible, porque el payload no está encriptado, con una simple decodificación con base64url se obtiene la información fácilmente.
```
    {
      "sub": "1",
      "name": "Martin",
      "iat": 1516239022
    }
```
- Y la tercera es la firma digital.

### Algoritmo y la firma digital

La firma digital va a depender principalmente del algoritmo utilizado. En el link anterior de IEFT podemos encontrar las estandarizaciones de los algoritmos que se aplican a los JWT. Cada uno de estos algoritmos nos proveen de distintas estrategias para realizar JWTs seguros.

Para continuar con lo aprendido en la sección de Public Key Cryptography, vamos a usar la especificación [RS256](), que nos indica que:
- Necesitamos tener una clave privada y una pública de tipo `rsa`.
- Usaremos la función de hashing `'sha256` para obtener los headers payload y data.

### Flujo de JWT

Antes de comenzar con un poco de código, veamos como es el flujo de los JWT a la hora de validar identidad:

1) Cliente requiere inicio de sesión
2) Servidor revisa validez de credenciales 
3) Si son válidas crea un JWT que envía al cliente
4) Cliente guarda localmente el JWT
5) Cliente adjunta el JWT a cada petición siguiente que realice
6) Si la ruta está protegida, servidor revisa la validez del JWT.
7) Si el JWT es válido, devuelve la información requerida.

### JWT en JavaScript

Apliquemos la teoría al código para asentar lo conocimientos sobre JWT. Cómo hicimos con el ejemplo en la firma digital, vamos a simular el envío de un JWT exportando e importando módulos.

El primer paso es instalar la librería base64url para codificar nuestra información.
Creamos un nuevo directorio y primero escribimos el código para generar y enviar nuestro primer JWT:
```js
// server/JWT/issueJWT.js
const base64url = require('base64url');
const crypto = require('crypto');
const fs = require('fs');

// Queremos generar un JWT con esta información
const header = {
    alg: 'RS256',
    type: 'JWT'
}
const payload =  {
    sub: '1',
    name: 'Martin',
    iat: 1516239022
}
// Primero debemos convertir los objetos a formato string
// para poder trabajar con ellos
const headerString = JSON.stringify(header);
const payloadString = JSON.stringify(payload);
// La información sigue en formato json
// por lo que ahora debemos codificar en formato base64url
const headerBase64url = base64url(headerString);
const payloadBase64url = base64url(payloadString);
// El siguiente paso es generar un hash con esos dos datos
// y luego firmarlo.
// Creamos una función de firma con el algoritmo especificado
const signatureFunction = crypto.createSign('RSA-SHA256');
// Pasamos nuestra información para generar el primer hash
signatureFunction.write(headerBase64url + '.' + payloadBase64url);
signatureFunction.end()
// Luego cargamos nuestra clave privada
const PRIV_KEY =  fs.readFileSync(__dirname + '/../cryptography/id_rsa_priv.pem','utf8');
// Y generamos la firma de nuestro JWT combinando el hash
// con nuestra clave privada
const signatureBase64 = signatureFunction.sign(PRIV_KEY, 'base64');
// Convertimos el encoding de nuestra
// firma de base64 a base64url
const signatureBase64url = base64url.fromBase64(signatureBase64);
// Y por último juntamos las piezas para armar nuestro JWT
const JWT = headerBase64url + '.' + payloadBase64url + '.' + signatureBase64url;

// Simulamos el envío del JWT
module.exports = {
    JWT
}
```
Para que nuestro JWT tenga sentido, ahora creamos nuestro código para verificar su validez:
```js
// server/JWT/verify.js
const base64url = require('base64url');
const crypto = require('crypto');
const fs = require('fs');

// Importamos el JWT
const { JWT } = require('./issueJWT');
// Separamos el JWT en cada una de sus partes
const jwtParts =  JWT.split('.');
const headerInBase64Url    = jwtParts[0];
const payloadInBase64Url   = jwtParts[1];
const signatureInBase64Url = jwtParts[2];

// Generamos una función para verificar nuestro token
// siguiendo un procedimiento similar a cuando creamos el token
const verifyFunction = crypto.createVerify('RSA-SHA256')
verifyFunction.write(headerInBase64Url + '.' + payloadInBase64Url);
verifyFunction.end();
// Debido a que crypto no maneja base64url,
// debemos convertir nuestra firma a base64
const signatureBase64 = base64url.toBase64(signatureInBase64Url);
// Cargamos nuestra clave pública
const PUB_KEY =  fs.readFileSync(__dirname + '/../cryptography/id_rsa_pub.pem','utf8');
// Y realizamos el último paso para verificar la validez de nuestro token
// Si es válido retornará true
// Y si la información fue manipulada de alguna manera, retornará false
const signatureIsValid = verifyFunction.verify(PUB_KEY, signatureBase64, 'base64')

console.log(signatureIsValid);
```

Si hicimos todo bien, se imprimirá `true` en la consola y podemos dar por válido el JWT y la información que contiene. 

#### jsonwebtoken

Existe una librería que hace todo este trabajo por nosotros, sin tener, por ejemplo, que convertir entre base64 y base64url para poder hashear o desencriptar nuestro token. Esta libreria es `jsonwebtoken` y ahora que ya sabemos los conceptos de como se construye un JWT, veamos como podemos aplicar esta libreria:

```js
// server/JWT/jsonwebtoken.js
// npm i jsonwebtoken
const jwt = require('jsonwebtoken');
const fs = require('fs');

const PRIV_KEY = fs.readFileSync(__dirname + '/../cryptography/id_rsa_priv.pem','utf8');
const PUB_KEY  = fs.readFileSync(__dirname + '/../cryptography/id_rsa_pub.pem','utf8');

// Mismo payload que nuestro JWT manual
const payload =  {
    sub: '1',
    name: 'Martin',
    iat: 1516239022
}

// Método para generar el JWT
// No necesitamos escribir el header
// la librería se encarga automáticamente.
const signedJWT = jwt.sign(payload, PRIV_KEY, { algorithm: 'RS256' });

// Método para verificar la validez del token
jwt.verify(signedJWT, PUB_KEY, { algorithm: ['RS256'] },(err, payload)=>{
    console.log(err);
    console.log(payload);
});
```

Hasta aquí hemos visto como se generan y están formados los JWT y una breve explicación de como se usa la criptografía para crear y verificar tokens seguros. Ahora podemos adentrarnos en la aplicación de Passport JS, con la seguridad de entender que es lo que está sucediendo por dentro y no simplemente implementar y rogar por que todo funcione.

## Passport-jwt

### Qué es [Passport](http://www.passportjs.org/)

Passport se prensenta en su sitio como un middleware para Node.js, utilizable en aplicaciones con Express. Se encarga de manejar la lógica de autenticación según el método que elijamos (JWT, Local, Facebook, etc.) y que se denominan estrategias. 

En nuestro caso, vamos a utilizar Passport para implementar una estrategia de JWT. Su funcionamiento interno lo vimos en las secciones anteriores de esta guía. Además de estar ahorrandonos escribir todo ese código en nuestras aplicaciones, Passport nos va a proveer directamente de un __middleware__ que se encargará de extraer el token de los headers, manejar errores y aceptar o rechazar la conexión dependiendo de la validez del JWT.

### Configuración inicial

Cada estrategia de Passport necesita de la librería passport y de su propio código. Por lo que antes de comenzar debemos ejecutar `npm i passport passport-jwt`.

Una vez instaladas las librerías, vamos a continuar con el código que creamos en la primer sección de esta guía. Agregamos passport a app.js:
```js
// server/app.js

const express = require('express');
const app = express();

const morgan = require('morgan');
const cors = require('cors');

/***** MIDDLEWARES ******/
app.use(morgan('dev'));
app.use(express.json());
app.use(cors());

/***** PASSPORT *********/
const passport = require('passport');
// Importamos la función de nuestro archivo passport.js que vamos 
// a ver a continuación y le pasamos el objeto importado de 
// la librería
require('./passport')(passport)

// Iniciamos passport, requerido para cualquier estrategia
app.use(passport.initialize());

/***** RUTAS ************/
app.use('/',require('./routes'))

module.exports = app;
```
### Verificación de JWT

El siguiente código es el que se está importando en nuestra app antes de inicialiar passport. Es lo que se va a ejecutar cada vez que se encuentre el middleware `passport.authenticate()` en una ruta protegida y que va a validar o no el JWT de la petición.

```js
// server/passport

const fs = require('fs');
const passport = require('passport');
const { User } = require('../db');
// Importamos la estrategia
const JwtStrategy = require('passport-jwt').Strategy;
// Y el método para extraer el JWT de la petición
const ExtractJwt = require('passport-jwt').ExtractJwt;

const PUB_KEY =  fs.readFileSync(__dirname + '/../cryptography/id_rsa_pub.pem','utf8');

// Definimos nuestras opciones. Todas las posibilidades
// se encuentran en la documentación de passport-jwt
// y están relacionadas con el uso de jsonwebtoken,
// de donde se debe extraer el token y el algoritmo a utilizar
const options = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: PUB_KEY,
    algorithms: ['RS256']
};

// Creamos una instancia de la estrategia a la que le pasamos nuestras opciones
// y una función callback que se ejecuta si el JWT es válido.
const strategy =  new JwtStrategy(options, (payload, done) => {
    User.findOne({ where: { ID: payload.sub } })
        .then((user)=>{
            if (user) return done(null, user);
            else return done(null, false)
        }).catch((err)=>{ done(err,null) });
});

// Exportamos la función que toma un objeto passport
// y lo devuelve con la estrategia que hemos definido
module.exports = (passport) => {
    passport.use(strategy)
}
```
En este caso elegimos ese método de extracción del token porque vamos a agregarlo en los Authorization Header de nuestras peticiones.

### Emitir JWT

Necesitamos una función que genere un JWT válido para el usuario que está queriendo loguearse a nuestro sitio.
En `server/routes/utils` (donde tenemos nuestra funciones de validación y generación de passwords) agregamos el siguiente código:

```js
// server/routes/utils/index.js

const fs = require('fs');
const jwt = require('jsonwebtoken');

const PRIV_KEY = fs.readFileSync(__dirname + '/../../cryptography/id_rsa_priv.pem')

const issueJWT = (user) => {
    const ID = { user };
    
    // Definimos la duración de la validez del JWT en 1 día
    // y agregamos el claim 'iat' que nos indica cuando fue emitido el token 
    const expiresIn = '1d';
    const payload =  {
        sub: ID,
        iat: Date.now()
    };

    // Usamos la librería jsonwebtoken para firmar nuestro token
    // como hicimos antes y agregamos la opción de expiración
    const signedToken = jwt.sign(payload, PRIV_KEY, { expiresIn, algorithm: 'RS256' });

    // Agregamos la palabra Bearer delante del JWT, ya que definimos
    // agregar nuestro token a las peticiones de esta manera
    return {
        token: 'Bearer ' + signedToken,
        expires: expiresIn
    }

};

module.exports = {
    genPassword,
    validatePassword,
    issueJWT
};
```
Y ahora que tenemos nuestro generador de JWT lo agregamos a la ruta `POST /signin`:

```js
// server/routes

const { issueJWT } = require('./utils');

router.post('/signin', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ where: { email } });
        if (!user) return res.status(401).json({ message: 'El usuario no existe.' })

        const validation = validatePassword(password, user.hashed_password, user.salt)
        if (!validation) return res.status(401).json({ message: 'Password incorrecta.' })

        // Usamos la función y desestructuramos la respuesta 
        // solo para ver lo que devuelve
        const { token, expiresIn } = issueJWT(user)

        // Agregamos el token y su duración en la respuesta
        res.json({
            success: true,
            email: user.email,
            token,
            expiresIn
        })
    } catch(err) { res.sendStatus(500) }

});
```
Si el usuario se ha logueado correctamente, se enviará el token correspondiente.
El último paso de esta guía es aplicar el middleware de passport.
Colocamos en los paramatros de `passport.authenticate()` colocamos primero el tipo de estrategia y luego `{ session: false }`, que le indica a Passport que no se está utilizando un sistema de sesiones, que podrían utilizarse con otras estrategias como la local.
```js
// server/routes
router.get('/mydata', passport.authenticate('jwt',{ session: false }) ,(req, res) => {
    res.json({ message: 'El Json Web Token es válido, felicitaciones!' })
});

```
Un petición con un JWT luce de esta manera:
```http
GET http://localhost:3001/mydata
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsImlhdCI6MTYzMjg4NjEwOTM2NywiZXhwIjoxNjMyODg2MTk1NzY3fQ.JN0b3lbVGFz7jp_7IW0b4Fh2jrAWKdrlQ-4LIE9YXuXJ3J8mpbZDCfMYUGhtQLvVywZI-S5dLzTLsOkx1jESwTEeGfLY_tIZJ4gY_TayQTGriEN5TzNVncslAkzCu_bmBrCbHhItJk1amJ4xeNPiHzcqoO2SinSMaGzHdkz1GCJM6XaRI9OAaFXgaZ1X5U8YpT-riFfg8kzYJsJUUyoeWCDluujrO_u0JRtIE1yOztVRIgGoApFdMnXGlBvcFJiXt66E3v6mJz6A7HPilKw_6mpd7MzomD9EdkHZt0Hbp_v0yFHdkUi-8PGZbhWY7DOZOCEGmD9bWeuL9YoaFgIiDx5G7wP-3kDqv0t2dPnq6nNAxJ_jZqbopC0at3P9U_Uwq58HSara7PrZtV7RW3vGubK1pSnQuWmoFFXcgDeGUFJ7E7gt02JFhhvrAC--ND2QrF3TslMYtAjvefziXgixDu7TVM3VMSzmGMGQNbogrQyVHXgRg1XAJdjm3r97HpmgKPBdtRT5tIqjkvHfoxxEO2HKCfNpCn4n55tOzp1ZSPV_cnHyoN4u9gMt745LEsgJPDOetHqrbvLe5aTNIbTKIyuSZdCjV1dghk26fI6dGl4eKBW5jjMuMc2bqc6mIEvUata2fZk97O9d1YhLOoHfM45yjjRUye83XOHZuWXTaHQ
```

Si nuestro token es válido, la ruta responderá satisfactoriamente, en caso contrario, Passport se encargará de devolver un status 401 Unauthorized, impidiendo el acceso a la ruta solicitada.

## Conclusión

