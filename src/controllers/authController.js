const { User } = require('../../database/models')

const nodemailer = require('nodemailer')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const axios = require('axios')
require('dotenv').config()

// Configuração do Nodemailer para enviar e-mails
const transporter = nodemailer.createTransport({
  service: 'gmail',
  host: 'smtp.forwardemail.net',
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  }
})

// Api key
const api_Key = process.env.API_KEY

// Rota de registro
exports.register = async (req, res) => {
  const { username, email, password } = req.body

  // Verifica se os campos estão preenchidos
  if (!username || !email || !password) {
    return res
      .status(400)
      .json({ message: 'Username, email, and password are required' })
  }

  // Verifica se existe uma conta com esse email
  const userExists = await User.findOne({ where: { email } })
  if (userExists) {
    return res
      .status(200)
      .json({ exists: true, message: 'O email já possui uma conta.' })
  }

  try {
    const response = await axios.get(
      `https://api.zerobounce.net/v2/validate?api_key=${api_Key}&email=${email}`
    )

    // Analise a resposta da API
    const result = response.data
    if (result.status === 'invalid') {
      return res.status(400).json({ message: 'O email não é válido' })
    }

    // Gera um código de confirmação aleatório
    const confirmationCode = Math.floor(1000 + Math.random() * 9000).toString()

    //  Envio do código de confirmação por e-mail
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Confirmação de Registro',
      text: `Seu código de confirmação é: ${confirmationCode}`
    }

    transporter.sendMail(mailOptions, async error => {
      if (error) {
        return res
          .status(500)
          .json({ message: 'Erro ao enviar o e-mail de confirmação' })
      }
      // Armazena a Senha de forma segura no banco de dados
      const hashedPassword = await bcrypt.hash(password, 10)

      // Armazena os dados do usuário no banco de dados, incluindo o código de redefinição de senha
      const user = await User.create({
        username,
        email,
        password: hashedPassword,
        confirmationCode,
        isConfirmed: false
      })
      res
        .status(201)
        .json({ message: 'Código de confirmação enviado por e-mail' })
    })
  } catch (error) {
    res.status(500).json({ message: 'Erro ao registrar o usuário' })
  }
}
// Rota de Verificação de registro
exports.verify = async (req, res) => {
  const { email, confirmationCode } = req.body

  // Verifica se todos os campos estao preenchidos
  if (!email || !confirmationCode) {
    return res
      .status(400)
      .json({ message: 'Email and confirmation code are required' })
  }

  // Verifica se o codigo de confirmacao pelo banco de dados
  const user = await User.findOne({
    where: { email, confirmationCode }
  })
  if (!user) {
    return res.status(400).json({ message: 'Código de confirmação inválido' })
  }

  // Atualiza os dados do usuário para confirmado e remove o código de confirmação
  user.isConfirmed = true
  user.confirmationCode = null
  await user.save()

  // Gera um token JWT para autenticação
  const token = jwt.sign({ email: user.email }, process.env.SECRECT_TOKEN, {
    expiresIn: '1h'
  })

  // Envia o token no cabeçalho da resposta
  res.setHeader('Authorization', `Bearer ${token}`)
  res.status(200).send('Registro concluído com sucesso.')
}
// Rota de Login
exports.login = async (req, res) => {
  const { email, password } = req.body

  //Verifica se todos os campos estao preenchidos
  if (!email || !password) {
    return res.status(400).send('Email and password are required')
  }

  // Verifica se as credenciais são válidas
  const user = await User.findOne({ where: { email } })
  if (!user) {
    return res.status(401).send('Email inválido.')
  }

  // Verificar se a Conta esta confirmada
  if (user.isConfirmed == false) {
    return res
      .status(401)
      .send(
        'Sua conta ainda não foi confirmada. Verifique seu email e confirme sua conta.'
      )
  }

  try {
    // Verifica a senha usando bcrypt
    const passwordMatch = await bcrypt.compare(password, user.password)
    if (!passwordMatch) {
      return res.status(401).send('Credenciais inválidas')
    }

    // Gera um token JWT para autenticação
    const token = jwt.sign({ email: user.email }, process.env.SECRECT_TOKEN, {
      expiresIn: '1h'
    })

    // Envia o token no cabeçalho da resposta
    res.setHeader('Authorization', `Bearer ${token}`)
    res.status(200).send('Login bem-sucedido')
  } catch (error) {
    console.error(error) // Adicione um log para depuração
    return res.status(500).send('Erro ao verificar a senha')
  }
}
