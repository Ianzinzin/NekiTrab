import React from 'react';
import { toast, ToastContainer } from 'react-toastify';
import styles from './CadastroModal.module.css';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCheck, faClose } from '@fortawesome/free-solid-svg-icons';
import { cadastrarSkill } from '../../Pages/sevice/skill';
import { ExceptHook } from '../../Hook.js/ExeptHook'; 

export const ModalCadastrar = ({ close }) => {
  const [arquivo, setArquivo] = React.useState(undefined);
  const [fileSelected, setFileSelected] = React.useState(false);
  const [skill, setSkill] = React.useState({ nome: '', descricao: '' });

  const handleChange = (e) => {
    const { name, value } = e.target;
    setSkill({ ...skill, [name]: value });
  };

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    setArquivo(file);
    setFileSelected(!!file);
  };

  const handleCadastrar = (e) => {
    e.preventDefault();
    cadastrarSkill(skill, arquivo)
      .then(() => toast.success('A skill foi cadastrada com sucesso!'))
      .catch((err) => toast.error(ExceptHook(err)));
  };

  return (
    <div className={styles.container}>
      <div className={styles.modal}>
        <header className={styles.header}>
          <h1>Cadastrar Skill</h1>
          <FontAwesomeIcon onClick={close} className={styles.closeIcon} icon={faClose} />
        </header>
        <div className={styles.content}>
          <form onSubmit={handleCadastrar}>
            <label>
              Nome da Skill:
              <input
                required
                value={skill.nome}
                onChange={handleChange}
                type="text"
                name="nome"
                placeholder="Nome da Skill"
              />
            </label>
            <label>
              Descrição da Skill:
              <textarea
                required
                value={skill.descricao}
                onChange={handleChange}
                maxLength="150"
                name="descricao"
                placeholder="Descrição da Skill"
              />
            </label>
            <label htmlFor="file-upload" className={fileSelected ? styles.fileSelected : styles.fileUpload}>
              {fileSelected ? <FontAwesomeIcon icon={faCheck} /> : 'Enviar Arquivo'}
            </label>
            <p>{arquivo?.name}</p>
            <input
              id="file-upload"
              className={styles.fileInput}
              type="file"
              onChange={handleFileChange}
              accept="image/*"
            />
            <button type="submit">Cadastrar</button>
          </form>
        </div>
      </div>
      <ToastContainer />
    </div>
  );
};
