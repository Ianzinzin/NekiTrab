import React from 'react'
import styles from './Register.module.css'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { faEye, faUser } from '@fortawesome/free-solid-svg-icons'
import { cadastroApi } from '../sevice/Usuario'
import { toast, ToastContainer } from 'react-toastify'
import { Link, useNavigate } from 'react-router-dom'

export const CadastroPage = () => {
  const navigate = useNavigate()
  const [confirmaSenha, setConfirmaSenha] = React.useState('')
  const [mostrarSenha, setMostrarSenha] = React.useState(false)
  const [estadoSenha, setEstadoSenha] = React.useState('password')
  const [userInfo, setUserInfo] = React.useState({
    email: "",
    senha: "",
    role: "ADMIN",
  })

  const handleCadastro = async (e) => {
    e.preventDefault()
    if (userInfo.senha !== confirmaSenha) {
      // Apenas substitua o toast.error por um simples alerta
      alert('As senhas estão diferentes!')
      return
    }
    try {
      await cadastroApi(userInfo)
      toast.success("Cadastro efetuado com sucesso! Redirecionando para o login")
      setTimeout(() => navigate("/"), 3000)
    } catch (err) {
      // Apenas substitua o toast.error por um simples alerta
      alert('Houve um erro ao cadastrar-se no site')
    }
  }

  const handleSenhaVisivel = () => {
    setMostrarSenha(!mostrarSenha)
    setEstadoSenha(mostrarSenha ? 'password' : 'text')
  }

  const handleChange = (event) => {
    const { name, value } = event.target
    setUserInfo({ ...userInfo, [name]: value })
  }

  return (
    <div className={styles.container}>
      <div className={styles.wrapper}>
        <form onSubmit={handleCadastro}>
          <h1>Cadastro</h1>
          <div className={styles.inputBox}>
            <input name='email' value={userInfo.email} onChange={handleChange} type='email' placeholder='Email' required />
            <FontAwesomeIcon className={styles.icone} icon={faUser} />
          </div>
          <div className={styles.inputBox}>
            <input name='senha' value={userInfo.senha} onChange={handleChange} type={estadoSenha} placeholder='Senha' required />
            <FontAwesomeIcon className={styles.iconeSenha} onClick={handleSenhaVisivel} icon={faEye} />
          </div>
          <div className={styles.inputBox}>
            <input name='confirmaSenha' value={confirmaSenha} onChange={(e) => setConfirmaSenha(e.target.value)} type={estadoSenha} placeholder='Confirmar Senha' required />
            <FontAwesomeIcon className={styles.iconeSenha} onClick={handleSenhaVisivel} icon={faEye} />
          </div>
          <button type='submit'>Cadastrar</button>
          <div className={styles.linkLogin}>
            <p>Já tem uma conta? <Link to="/">Logar-se</Link></p>
          </div>
        </form>
      </div>
      <ToastContainer />
    </div>
  )
}
