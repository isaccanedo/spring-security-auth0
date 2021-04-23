### Segurança Spring com Auth0


# 1. Introdução
Auth0 fornece serviços de autenticação e autorização para vários tipos de aplicativos, como Native, Single Page Applications e Web. Além disso, permite a implementação de vários recursos, como Single Sign-on, Social Login e Multi-Factor Authentication.

Neste tutorial, vamos explorar Spring Security com Auth0 por meio de um guia passo a passo, junto com as principais configurações da conta Auth0.

# 2. Configurando Auth0
### 2.1. Auth0 Sign-Up
Primeiro, vamos assinar um plano Auth0 gratuito que fornece acesso para até 7 mil usuários ativos com logins ilimitados. No entanto, podemos pular esta seção se já tivermos uma:

### 2.2. Painel
Depois de fazer login na conta Auth0, veremos um painel que destaca os detalhes como atividades de login, logins mais recentes e novas inscrições:

### 2.3. Criar uma nova aplicação
Em seguida, no menu Aplicativos, criaremos um novo aplicativo OpenID Connect (OIDC) para Spring Boot.

Além disso, escolheremos os aplicativos regulares da Web como tipo de aplicativo entre as opções disponíveis, como aplicativos nativos, aplicativos de página única e aplicativos máquina a máquina:

### 2.4. Configurações do aplicativo
A seguir, configuraremos alguns URIs de aplicativo como URLs de retorno de chamada e URLs de logout apontando para nosso aplicativo:

### 2.5. Credenciais do cliente
Por fim, obteremos os valores do Domínio, ID do cliente e Segredo do cliente associados ao nosso aplicativo:

Mantenha essas credenciais à mão, pois elas são necessárias para a configuração do Auth0 em nosso Spring Boot App.

# 3. Configuração do aplicativo Spring Boot
Agora que nossa conta Auth0 está pronta com as principais configurações, estamos preparados para integrar a segurança Auth0 em um aplicativo Spring Boot.

### 3.1. Maven
Primeiro, vamos adicionar a dependência Maven mvc-auth-commons mais recente ao nosso pom.xml:

```
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>mvc-auth-commons</artifactId>
    <version>1.2.0</version>
</dependency>
```

### 3.2. Gradle
Da mesma forma, ao usar o Gradle, podemos adicionar a dependência mvc-auth-commons no arquivo build.gradle:

```
compile 'com.auth0:mvc-auth-commons:1.2.0'
```

### 3.3. application.properties
Nosso Spring Boot App requer informações como ID do cliente e segredo do cliente para permitir a autenticação de uma conta Auth0. Portanto, vamos adicioná-los ao arquivo application.properties:

```
com.auth0.domain: dev-example.auth0.com
com.auth0.clientId: {clientId}
com.auth0.clientSecret: {clientSecret}
```

### 3.4. AuthConfig
A seguir, criaremos a classe AuthConfig para ler as propriedades Auth0 do arquivo application.properties:

```
@Configuration
@EnableWebSecurity
public class AuthConfig extends WebSecurityConfigurerAdapter {
    @Value(value = "${com.auth0.domain}")
    private String domain;

    @Value(value = "${com.auth0.clientId}")
    private String clientId;

    @Value(value = "${com.auth0.clientSecret}")
    private String clientSecret;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http
          .authorizeRequests()
          .antMatchers("/callback", "/login", "/").permitAll()
          .anyRequest().authenticated()
          .and()
          .formLogin()
          .loginPage("/login")
          .and()
          .logout().logoutSuccessHandler(logoutSuccessHandler()).permitAll();
    }
}
```

Além disso, a classe AuthConfig é configurada para habilitar a segurança da web estendendo a classe WebSecurityConfigurerAdapter.

### 3.5. AuthenticationController
Por último, adicionaremos uma referência de bean para a classe AuthenticationController à classe AuthConfig já discutida:

```
@Bean
public AuthenticationController authenticationController() throws UnsupportedEncodingException {
    JwkProvider jwkProvider = new JwkProviderBuilder(domain).build();
    return AuthenticationController.newBuilder(domain, clientId, clientSecret)
      .withJwkProvider(jwkProvider)
      .build();
}
```

Aqui, usamos a classe JwkProviderBuilder ao construir uma instância da classe AuthenticationController. Usaremos isso para buscar a chave pública para verificar a assinatura do token (por padrão, o token é assinado usando o algoritmo de assinatura assimétrica RS256).

Além disso, o bean authenticationController fornece uma URL de autorização para login e lida com a solicitação de retorno de chamada.

# 4. AuthController
A seguir, criaremos a classe AuthController para recursos de login e retorno de chamada:


```
@Controller
public class AuthController {
    @Autowired
    private AuthConfig config;

    @Autowired 
    private AuthenticationController authenticationController;
}
```

Aqui, injetamos as dependências das classes AuthConfig e AuthenticationController discutidas na seção anterior.

### 4.1. Conecte-se
Vamos criar o método de login que permite ao nosso Spring Boot App autenticar um usuário:

```
@GetMapping(value = "/login")
protected void login(HttpServletRequest request, HttpServletResponse response) {
    String redirectUri = "http://localhost:8080/callback";
    String authorizeUrl = authenticationController.buildAuthorizeUrl(request, response, redirectUri)
      .withScope("openid email")
      .build();
    response.sendRedirect(authorizeUrl);
}
```

O método buildAuthorizeUrl gera a URL de autorização do Auth0 e redireciona para uma tela de login padrão do Auth0.

### 4.2. Ligue de volta
Depois que o usuário fizer login com as credenciais Auth0, a solicitação de retorno de chamada será enviada ao nosso aplicativo Spring Boot. Para isso, vamos criar o método de retorno de chamada:

```
@GetMapping(value="/callback")
public void callback(HttpServletRequest request, HttpServletResponse response) {
    Tokens tokens = authenticationController.handle(request, response);
    
    DecodedJWT jwt = JWT.decode(tokens.getIdToken());
    TestingAuthenticationToken authToken2 = new TestingAuthenticationToken(jwt.getSubject(),
      jwt.getToken());
    authToken2.setAuthenticated(true);
    
    SecurityContextHolder.getContext().setAuthentication(authToken2);
    response.sendRedirect(config.getContextPath(request) + "/"); 
}
```

Lidamos com a solicitação de retorno de chamada para obter o accessToken e o idToken que representam a autenticação bem-sucedida. Em seguida, criamos o objeto TestingAuthenticationToken para definir a autenticação em SecurityContextHolder.

No entanto, podemos criar nossa implementação da classe AbstractAuthenticationToken para melhor usabilidade.

# 5. HomeController
Por último, criaremos o HomeController com um mapeamento padrão para nossa página de destino do aplicativo:

```
@Controller
public class HomeController {
    @GetMapping(value = "/")
    @ResponseBody
    public String home(final Authentication authentication) {
        TestingAuthenticationToken token = (TestingAuthenticationToken) authentication;
        DecodedJWT jwt = JWT.decode(token.getCredentials().toString());
        String email = jwt.getClaims().get("email").asString();
        return "Welcome, " + email + "!";
    }
}
```

Aqui, extraímos o objeto DecodedJWT do idToken. Além disso, as informações do usuário, como e-mail, são obtidas nas reivindicações.

É isso! Nosso Spring Boot App está pronto com suporte de segurança Auth0. Vamos executar nosso aplicativo usando o comando Maven:

```
mvn spring-boot:run
```

Ao acessar o aplicativo em localhost:8080/login, veremos uma página de login padrão fornecida por Auth0:

Uma vez conectado com as credenciais do usuário registrado, uma mensagem de boas-vindas com o e-mail do usuário será exibida:

Além disso, encontraremos um botão “Cadastre-se” (ao lado de “Login”) na tela de login padrão para autorregistro.

# 6. Inscreva-se
### 6.1. Autorregistro
Pela primeira vez, podemos criar uma conta Auth0 usando o botão “Sign Up” e, em seguida, fornecendo informações como e-mail e senha:

### 6.2. Criar um usuário
Ou podemos criar um novo usuário a partir do menu Usuários na conta Auth0:

### 6.3. Configurações de conexões
Além disso, podemos escolher vários tipos de conexões, como banco de dados e login social para inscrição/login em nosso aplicativo Spring Boot:

Além disso, uma variedade de conexões sociais estão disponíveis para você escolher:

# 7. LogoutController
Agora que vimos os recursos de login e retorno de chamada, podemos adicionar um recurso de logout ao nosso aplicativo Spring Boot.

Vamos criar a classe LogoutController implementando a classe LogoutSuccessHandler:

```
@Controller
public class LogoutController implements LogoutSuccessHandler {
    @Autowired
    private AuthConfig config;

    @Override
    public void onLogoutSuccess(HttpServletRequest req, HttpServletResponse res, 
      Authentication authentication) {
        if (req.getSession() != null) {
            req.getSession().invalidate();
        }
        String returnTo = "http://localhost:8080/";
        String logoutUrl = "https://dev-example.auth0.com/v2/logout?client_id=" +
          config.getClientId() + "&returnTo=" +returnTo;
        res.sendRedirect(logoutUrl);
    }
}
```

Aqui, o método onLogoutSuccess é sobrescrito para chamar a URL de logout/v2/logout Auth0.

# 8. API de gerenciamento Auth0
Até agora, vimos a integração de segurança do Auth0 no Spring Boot App. Agora, vamos interagir com a API Auth0 Management (API do sistema) no mesmo aplicativo.

### 8.1. Criar uma nova aplicação
Primeiro, para acessar a API de gerenciamento do Auth0, criaremos um aplicativo máquina para máquina na conta do Auth0:

### 8.2. Autorização
Em seguida, adicionaremos autorização à API de gerenciamento Auth0 com permissões para ler/criar usuários:

### 8.3. Credenciais do cliente
Por fim, receberemos o ID do cliente e o segredo do cliente para acessar o aplicativo de gerenciamento Auth0 de nosso aplicativo Spring Boot:

### 8.4. Token de acesso
Vamos gerar um token de acesso para o aplicativo de gerenciamento Auth0 usando credenciais de cliente recebidas na seção anterior:

```
public String getManagementApiToken() {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);

    JSONObject requestBody = new JSONObject();
    requestBody.put("client_id", "auth0ManagementAppClientId");
    requestBody.put("client_secret", "auth0ManagementAppClientSecret");
    requestBody.put("audience", "https://dev-example.auth0.com/api/v2/");
    requestBody.put("grant_type", "client_credentials"); 

    HttpEntity<String> request = new HttpEntity<String>(requestBody.toString(), headers);

    RestTemplate restTemplate = new RestTemplate();
    HashMap<String, String> result = restTemplate
      .postForObject("https://dev-example.auth0.com/oauth/token", request, HashMap.class);

    return result.get("access_token");
}
```

Aqui, fizemos uma solicitação REST para a URL do token Auth0/oauth token para obter os tokens de acesso e atualização.

Além disso, podemos armazenar essas credenciais de cliente no arquivo application.properties e lê-lo usando a classe AuthConfig.

### 8.5. UserController
Depois disso, vamos criar a classe UserController com o método de usuários:

```
@Controller
public class UserController {
    @GetMapping(value="/users")
    @ResponseBody
    public ResponseEntity<String> users(HttpServletRequest request, HttpServletResponse response) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "Bearer " + getManagementApiToken());
        
        HttpEntity<String> entity = new HttpEntity<String>(headers);
        
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> result = restTemplate
          .exchange("https://dev-example.auth0.com/api/v2/users", HttpMethod.GET, entity, String.class);
        return result;
    }
}
```

O método users busca uma lista de todos os usuários fazendo uma solicitação GET à API /api/v2/users Auth0 com o token de acesso gerado na seção anterior.

Então, vamos acessar localhost:8080/users para receber uma resposta JSON contendo todos os usuários:

```
[{
    "created_at": "2020-05-05T14:38:18.955Z",
    "email": "ansh@bans.com",
    "email_verified": true,
    "identities": [
        {
            "user_id": "5eb17a5a1cc1ac0c1487c37f78758",
            "provider": "auth0",
            "connection": "Username-Password-Authentication",
            "isSocial": false
        }
    ],
    "name": "ansh@bans.com",
    "nickname": "ansh",
    "logins_count": 64
    // ...
}]
```

### 8.6. Criar usuário
Da mesma forma, podemos criar um usuário fazendo uma solicitação POST para a /api/v2/users Auth0 API:

```
@GetMapping(value = "/createUser")
@ResponseBody
public ResponseEntity<String> createUser(HttpServletResponse response) {
    JSONObject request = new JSONObject();
    request.put("email", "norman.lewis@email.com");
    request.put("given_name", "Norman");
    request.put("family_name", "Lewis");
    request.put("connection", "Username-Password-Authentication");
    request.put("password", "Pa33w0rd");
    
    // ...
    ResponseEntity<String> result = restTemplate
      .postForEntity("https://dev-example.auth0.com/api/v2/users", request.toString(), String.class);
    return result;
}
```

Então, vamos acessar localhost:8080/createUser e verificar os detalhes do novo usuário:

```
{
    "created_at": "2020-05-10T12:30:15.343Z",
    "email": "norman.lewis@email.com",
    "email_verified": false,
    "family_name": "Lewis",
    "given_name": "Norman",
    "identities": [
        {
            "connection": "Username-Password-Authentication",
            "user_id": "5eb7f3d76b69bc0c120a8901576",
            "provider": "auth0",
            "isSocial": false
        }
    ],
    "name": "norman.lewis@email.com",
    "nickname": "norman.lewis",
    // ...
}
```

Da mesma forma, podemos realizar várias operações, como listar todas as conexões, criar uma conexão, listar todos os clientes e criar um cliente usando APIs Auth0, dependendo de nossas permissões.

# 9. Conclusão
Neste tutorial, exploramos Spring Security com Auth0.

Primeiro, configuramos a conta Auth0 com configurações essenciais. Em seguida, criamos um Spring Boot App e configuramos o application.properties para integração do Spring Security com Auth0.

Em seguida, examinamos a criação de um token de API para a API de gerenciamento Auth0. Por último, examinamos recursos como buscar todos os usuários e criar um usuário.