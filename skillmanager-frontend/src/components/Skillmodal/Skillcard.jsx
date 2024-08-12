import React, { useState } from 'react';
import styles from '../Skillmodal/Skillcard.module.css';

export default function CardSkill({ props, handleDeletar, handleAtualizar }) {
    const [nivel, setNivel] = useState(props.nivel);
    const nomeSkill = props.skill.nome;
    const novoNome = nomeSkill.length > 37 ? `${nomeSkill.substring(0, 37)}...` : nomeSkill;

    const removerSkill = () => handleDeletar(props.skill.id);
    const handleUpdateNivel = () => handleAtualizar(props.skill.id, nivel);

    return (
        <div className={styles.container}>
            <div className={styles.imgArea}>
                <img src={props.skill.url} alt={novoNome} className={styles.skillImage} />
            </div>
            <div className={styles.contentArea}>
                <h3 className={styles.title}>{novoNome}</h3>
                <p className={styles.descricao}>{props.skill.descricao}</p>
                <div className={styles.nivelArea}>
                    <label htmlFor="nivel">Nível:</label>
                    <input
                        id="nivel"
                        type="number"
                        value={nivel}
                        onChange={(e) => setNivel(e.target.value)}
                        min="0"
                        max="10"
                        className={styles.inputNivel}
                    />
                </div>
                <div className={styles.buttonArea}>
                    <button onClick={removerSkill} className={styles.button}>
                        Remover Skill
                    </button>
                    <button
                        onClick={handleUpdateNivel}
                        className={styles.button}
                        disabled={nivel === props.nivel}
                    >
                        Atualizar Nível
                    </button>
                </div>
            </div>
        </div>
    );
}
