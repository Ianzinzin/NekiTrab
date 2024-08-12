import React, { useState, useEffect, useContext } from 'react';
import { toast, ToastContainer } from 'react-toastify';
import { listarTodasSkills } from '../../Pages/sevice/skill';
import { atribuirSkill } from '../../Pages/sevice/Usuario';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faClose, faTrash } from '@fortawesome/free-solid-svg-icons';
import { AuthContext } from '../../components/Context/AuthorizarionCont';
import useFetchUser from '../../Hook.js/useFetchUser';
import styles from './AddModal.module.css';

export const ModalAtribuir = ({ close, userId, reload }) => {
  const { user } = useContext(AuthContext);
  const fetchUser = useFetchUser(); // Corrigido para usar a função padrão
  const [skillsDisponiveis, setSkillsDisponiveis] = useState([]);
  const [skillsAtribuidas, setSkillsAtribuidas] = useState([]);
  const [buttonState, setButtonState] = useState(true);

  useEffect(() => {
    listarTodasSkills()
      .then((res) => {
        const novaLista = res.data.filter(
          (skillRes) => !user.skills.some((skillUser) => skillUser.skill.id === skillRes.id)
        );
        setSkillsDisponiveis(novaLista);
      })
      .catch((err) => toast.error('Erro ao carregar skills disponíveis'));
  }, [user.skills]);

  useEffect(() => {
    setButtonState(skillsAtribuidas.length === 0);
  }, [skillsAtribuidas]);

  const handleChange = (e) => {
    const skillId = e.target.value;
    const skillSelecionada = skillsDisponiveis.find((skill) => skill.id == skillId);
    if (skillSelecionada && !skillsAtribuidas.some((skill) => skill.skill.id === skillSelecionada.id)) {
      setSkillsAtribuidas([...skillsAtribuidas, { skill: skillSelecionada, nivel: 0 }]);
      toast.success(`${skillSelecionada.nome} adicionada com sucesso!`);
    } else {
      toast.error('Skill já atribuída ou inválida');
    }
  };

  const handleNivel = (selecionada, acao) => {
    selecionada.nivel = acao === 'adicionar' 
      ? Math.min(selecionada.nivel + 1, 10) 
      : Math.max(selecionada.nivel - 1, 0);
    setSkillsAtribuidas([...skillsAtribuidas]);
  };

  const handleRemoverSkill = (id) => {
    setSkillsAtribuidas(skillsAtribuidas.filter((skill) => skill.skill.id !== id));
    toast.success('Skill removida da lista com sucesso!');
  };

  const handleSalvar = () => {
    const info = {
      usuarioId: userId,
      skillsId: skillsAtribuidas.map((skill) => skill.skill.id),
      niveis: skillsAtribuidas.map((skill) => skill.nivel),
    };

    atribuirSkill(info)
      .then(() => {
        fetchUser(userId)
          .then(() => {
            reload(user.skills);
            toast.success('Skills atribuídas com sucesso!');
          })
          .catch((err) => toast.error('Erro ao atualizar o usuário'));
      })
      .catch((err) => toast.error('Erro ao atribuir skills'));
    setSkillsAtribuidas([]);
  };

  return (
    <div className={styles.containerModal}>
      <div className={styles.conteudoModal}>
        <div className={styles.header}>
          <select onChange={handleChange} defaultValue="">
            <option disabled value="">Selecione uma skill</option>
            {skillsDisponiveis.map((skill) => (
              <option key={skill.id} value={skill.id}>{skill.nome}</option>
            ))}
          </select>
          <FontAwesomeIcon onClick={close} className={styles.closeIcon} icon={faClose} />
        </div>
        <div className={styles.showList}>
          {skillsAtribuidas.map((selecionada) => (
            <div key={selecionada.skill.id} className={styles.configurar}>
              <span>{selecionada.skill.nome.length > 37 ? `${selecionada.skill.nome.substring(0, 37)}...` : selecionada.skill.nome}</span>
              <div className={styles.nivelArea}>
                <button onClick={() => handleNivel(selecionada, 'adicionar')}>+</button>
                <span>{selecionada.nivel}</span>
                <button onClick={() => handleNivel(selecionada, 'remover')}>-</button>
              </div>
              <FontAwesomeIcon onClick={() => handleRemoverSkill(selecionada.skill.id)} icon={faTrash} className={styles.botaoRemover} />
            </div>
          ))}
        </div>
        <div className={styles.buttonArea}>
          <button onClick={handleSalvar} disabled={buttonState}>Atribuir skills</button>
        </div>
      </div>
      <ToastContainer />
    </div>
  );
};
