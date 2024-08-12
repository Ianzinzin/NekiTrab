import React, { useState } from 'react';
import styles from './Home.module.css';
import Card from '../../components/Skillmodal/Skillcard';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faDoorOpen } from '@fortawesome/free-solid-svg-icons';
import { useNavigate } from 'react-router-dom';
import { toast, ToastContainer } from 'react-toastify';
import { ModalAtribuir } from '../../components/AddModal/AddModal';
import { ModalCadastrar } from '../../components/CadastroModal/CadastroModal';

export const HomePage = () => {
  const navigate = useNavigate();
  const [modalAtribuir, setModalAtribuir] = useState(false);
  const [modalCadastrar, setModalCadastrar] = useState(false);
  const [skills, setSkills] = useState([]); // Define habilidades como um array vazio ou com valores estáticos
  const [dropdownAtribuir, setDropdownAtribuir] = useState(false);
  const [dropdownSkill, setDropdownSkill] = useState(false);

  const handleDropdownAtribuir = () => {
    setDropdownAtribuir(!dropdownAtribuir);
    if (dropdownSkill) setDropdownSkill(false);
  };

  const handleDropdownSkill = () => {
    setDropdownSkill(!dropdownSkill);
    if (dropdownAtribuir) setDropdownAtribuir(false);
  };

  const handleModalAtribuir = () => {
    setModalAtribuir(!modalAtribuir);
    setDropdownAtribuir(false);
  };

  const handleModalCadastrar = () => {
    setModalCadastrar(!modalCadastrar);
    setDropdownSkill(false);
  };

  const handleLogout = () => {
    localStorage.removeItem('user');
    localStorage.removeItem('token');
    navigate('/');
  };

  const handleDeleteSkill = (idSelecionado) => {
    // Simulação de exclusão de skill
    const updatedSkills = skills.filter(skill => skill.id !== idSelecionado);
    setSkills(updatedSkills);
    toast.success('Skill removida com sucesso');
  };

  const handleAtualizarNivel = (skillId, novoNivel) => {
    // Simulação de atualização de nível
    const updatedSkills = skills.map(skill =>
      skill.id === skillId ? { ...skill, nivel: novoNivel } : skill
    );
    setSkills(updatedSkills);
  };

  return (
    <div className={styles.container}>
      <div className={styles.headerContent}>
        <p>Bem-vindo!</p>
        <ul className={styles.opcoes}>
          <li onClick={handleDropdownSkill}>Gerenciar Skills</li>
          <li onClick={handleDropdownAtribuir}>Atribuir Skill</li>
          {dropdownAtribuir && (
            <div className={styles.dropdown}>
              <ul className={styles.opcoesDropdown}>
                <li onClick={handleModalAtribuir}>Atribuir Skill</li>
              </ul>
            </div>
          )}
          {dropdownSkill && (
            <div className={styles.dropdownSkill}>
              <ul className={styles.opcoesDropdown}>
                <li onClick={handleModalCadastrar}>Cadastrar Skill</li>
                <li onClick={() => alert('Editar Skill')}>Editar Skill</li>
                <li onClick={() => alert('Remover Skill')}>Remover Skill</li>
              </ul>
            </div>
          )}
        </ul>
        <FontAwesomeIcon
          onClick={handleLogout}
          className={styles.icon}
          icon={faDoorOpen}
        />
      </div>
      <div className={styles.contentArea}>
        {skills.length > 0 ? (
          skills.map((skill) => (
            <Card
              key={skill.id}
              skill={skill}
              handleAtualizar={handleAtualizarNivel}
              handleDeletar={handleDeleteSkill}
            />
          ))
        ) : (
          <p role="button" onClick={handleModalAtribuir} className={styles.renderError}>
            Nada por aqui... Tente atribuir uma skill!
          </p>
        )}
      </div>
      {modalAtribuir && (
        <div className={styles.modalAtribuir}>
          <ModalAtribuir reload={setSkills} userId={null} close={handleModalAtribuir} />
        </div>
      )}
      {modalCadastrar && (
        <div className={styles.modalCadastrar}>
          <ModalCadastrar reload={setSkills} userId={null} close={handleModalCadastrar} />
        </div>
      )}
      <ToastContainer />
    </div>
  );
};
