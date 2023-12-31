﻿# Projeto de Autenticação 2FA com Node.js, Express e Sequelize


## Visão Geral

Este projeto é um sistema de autenticação de dois fatores (2FA) desenvolvido usando Node.js, Express e Sequelize. Ele permite que os usuários se registrem, validem seus e-mails e autentiquem suas contas com um código de acesso. Além disso, o sistema oferece autenticação segura com geração de tokens JWT para login.

## Tecnologias Utilizadas

- **Node.js e Express:** Utilizamos Node.js como ambiente de execução e Express como framework para criar o servidor web. Isso permitiu uma abordagem ágil e eficiente para o desenvolvimento.

- **Sequelize e Sequelize-CLI:** O Sequelize é um ORM que simplifica a interação com o banco de dados MySQL, permitindo a criação e manipulação programática de tabelas. O Sequelize-CLI facilitou a criação de migrações.

- **MySQL:** Como banco de dados principal, o MySQL foi usado para armazenar dados de usuários e configurações.

- **Axios:** Utilizamos a biblioteca Axios para realizar solicitações HTTP à API ZeroBounce, que verifica a validade dos endereços de e-mail durante o registro.

- **Nodemailer:** O Nodemailer foi essencial para enviar e-mails personalizados com códigos de acesso para os usuários, permitindo a confirmação de suas contas.

- **Bcrypt:** Para garantir a segurança das senhas dos usuários, realizei o hash das senhas antes de armazená-las no banco de dados.

- **JSON Web Tokens (JWT):** Implementei a autenticação dos usuários por meio de tokens JWT, garantindo a segurança no login e o acesso a recursos protegidos.

- **Jest, Supertest e Nodemon:** Desenvolvemos testes unitários abrangentes com Jest e Supertest para verificar a funcionalidade correta de todos os controladores de autenticação. O Nodemon foi útil durante o desenvolvimento, atualizando o servidor automaticamente após alterações no código.

## Fluxo do Sistema

1. **Registro (Rota `/register`):** Os usuários se registram fornecendo nome de usuário, endereço de e-mail e senha. O sistema verifica se todos os campos necessários estão preenchidos.

2. **Validação de E-mail:** O sistema utiliza a biblioteca Axios para fazer uma solicitação à API ZeroBounce, que verifica a validade do endereço de e-mail fornecido. Se o e-mail for válido, o fluxo continua.

3. **Envio de E-mail de Confirmação:** Após a validação, o sistema gera um código de confirmação aleatório e envia um e-mail personalizado para o usuário com esse código, permitindo que ele confirme sua conta.

4. **Verificação (Rota `/verify`):** O usuário envia seu endereço de e-mail e o código de confirmação recebido por e-mail para a rota `/verify`. O sistema verifica se o e-mail e o código correspondem aos registros no banco de dados.

5. **Autenticação e Token JWT:** Se o e-mail e o código de confirmação estiverem corretos, a conta do usuário é marcada como autenticada. O sistema então gera um token JWT que é enviado no cabeçalho da resposta.

6. **Login (Rota `/login`):** Para fazer login, o usuário fornece seu endereço de e-mail e senha. O sistema verifica se o e-mail existe no banco de dados e se a senha corresponde à versão hash armazenada.

7. **Geração de Token de Acesso:** Se as credenciais estiverem corretas, o sistema gera um token JWT, que é enviado no cabeçalho da resposta, permitindo que o usuário acesse recursos protegidos.

## Pré-requisitos

Certifique-se de que o seguinte software esteja instalado em seu sistema:

- [Node.js](https://nodejs.org/)
- [MySQL](https://www.mysql.com/)
- [NPM](https://www.npmjs.com/) (Normalmente instalado com o Node.js)
- [Git](https://git-scm.com/)

## Como Iniciar

Siga as etapas abaixo para iniciar o projeto em sua máquina local:

1. Clone o repositório:

`
git clone https://github.com/seu-usuario/seu-projeto.git
`

2. Navegue até o diretório do projeto:

  `
  cd seu-projeto
  `

3. Instale as dependências:

`
npm install
`

4. Crie um arquivo .env na raiz do projeto e adicione as variáveis de ambiente necessárias, como chaves de API, configurações de banco de dados e segredos JWT. Certifique-se de incluir as seguintes variáveis para configurar a conexão com o banco de dados:

```bash
DB_HOST=seu-host

DB_USER=seu-usuario

DB_PASSWORD=sua-senha

DB_DATABASE=seu-banco-de-dados

DB_PORT=porta-do-banco

```


5. Execute as migrações do Sequelize para criar as tabelas no banco de dados:

`
npx sequelize-cli db:migrate
`

6. Inicie o servidor:

`
npm start
`

O sistema estará disponível em http://localhost:8000 por padrão. Você pode personalizar a porta no arquivo `.env.

## Testes
O projeto inclui testes abrangentes para garantir a funcionalidade correta dos controladores de autenticação. Para executar os testes, utilize o seguinte comando:

`
npx test
`

## Conclusão
Este projeto foi uma aventura educativa, permitindo aprender e aplicar diversas tecnologias e conceitos, incluindo autenticação, segurança, integração com API externa e testes. Ao desenvolver este sistema de autenticação 2FA, foi possível adquirir experiência valiosa e superar desafios. A documentação abrangente e os testes garantem a robustez do projeto, tornando-o pronto para ser implantado em produção.

Sinta-se à vontade para contribuir, fornecer feedback ou utilizá-lo como base para seus próprios projetos de autenticação segura.
