import { View, Text, StyleSheet, ToastAndroid, ScrollView } from 'react-native';
import RNPickerSelect from 'react-native-picker-select';
import React, { useContext, useEffect, useState } from 'react';
import useFetchUser from '../../hooks/Hooks';
import { AuthContext } from '../../context/authContext';
import { listarTodasSkills } from '../../service/skill/skill';
import { SkillType, skillUserType } from '../../interfaces/TypesSkill';
import { atribuirSkill } from '../../service/usuario/usuario';
import { TouchableOpacity } from 'react-native-gesture-handler';
import { FontAwesomeIcon } from '@fortawesome/react-native-fontawesome';
import { faList, faLongArrowAltUp, faTrash } from '@fortawesome/free-solid-svg-icons';

interface modalAtribuirProps {
    reload: (skills: any) => void,
    userId: number,
    close: () => void,
}

interface skillLevelType {
    nivel: number,
    skill: SkillType
}

export default function ModalAtribuir({ reload, userId, close }: modalAtribuirProps) {
    const [selectedValue, setSelectedValue] = useState(null);
    const { user } = useContext(AuthContext);
    const fetchUser = useFetchUser();
    const [skillsDisponiveis, setSkillsDisponiveis] = React.useState([]);
    const [skillsAtribuidas, setSkillsAtribuidas] = useState<skillUserType[]>([]);
    const [novosObjetos, setNovosObjetos] = useState([]);

    useEffect(() => {
        listarTodasSkills().then((res) => {
            const novaLista = res.data.filter((skillRes: SkillType) =>
                !user.skills.some((skillUser: skillUserType) => skillUser.skill.id === skillRes.id)
            );

            const novos = novaLista.map((element: SkillType) => ({
                label: element.nome,
                value: element.id
            }));

            setSkillsDisponiveis(novaLista);
            setNovosObjetos(novos);
        }).catch((err) => console.log('deu erro', err));
    }, [user.skills]);

    const handleSubstring = (selecionada: skillLevelType) => {
        const nome = selecionada.skill.nome;
        return nome.length > 18 ? `${nome.substring(0, 18)}...` : nome;
    }

    const handleRemoverSkill = (id: number) => {
        const novaLista = skillsAtribuidas.filter(skill => skill.skill.id !== id);
        setSkillsAtribuidas(novaLista);
        ToastAndroid.showWithGravity('Skill removida da lista com sucesso!', ToastAndroid.TOP, ToastAndroid.SHORT);
    }

    const handleNivel = (
        selecionada: skillLevelType,
        acao: 'adicionar' | 'remover'
    ) => {
        let novoNivel = selecionada.nivel;

        if (acao === 'adicionar') {
            novoNivel = novoNivel < 10 ? novoNivel + 1 : novoNivel;
        } else if (acao === 'remover') {
            novoNivel = novoNivel > 0 ? novoNivel - 1 : novoNivel;
        }

        setSkillsAtribuidas((prevSkills) =>
            prevSkills.map((skill) =>
                skill.skill.id === selecionada.skill.id
                    ? { ...skill, nivel: novoNivel }
                    : skill
            )
        );
    };

    const handleChange = (value: any) => {
        const skillSelecionada: skillUserType = {
            skill: skillsDisponiveis.find((skill: SkillType) => skill.id === value) || null,
            nivel: 0,
        };

        if (skillSelecionada.skill && !skillsAtribuidas.some((skill: skillUserType) => skill.skill.id === skillSelecionada.skill.id)) {
            setSkillsAtribuidas([...skillsAtribuidas, skillSelecionada]);
            ToastAndroid.showWithGravity(`${skillSelecionada.skill.nome} adicionada com sucesso!`, ToastAndroid.TOP, ToastAndroid.SHORT);
        } else {
            ToastAndroid.showWithGravity('Skill já atribuída ou inválida', ToastAndroid.TOP, ToastAndroid.SHORT);
        }
    };

    const handleSalvar = () => {
        const skillsSalvar: any = [];
        const niveis: any = [];
        skillsAtribuidas.forEach((skill) => {
            skillsSalvar.push(skill.skill.id);
            niveis.push(skill.nivel);
        });

        const info = {
            usuarioId: userId,
            skillsId: skillsSalvar,
            niveis: niveis
        };
        atribuirSkill(info).then((res) => fetchUser(userId))
            .catch((err) => ToastAndroid.showWithGravity('Erro ao atribuir skills.', ToastAndroid.TOP, ToastAndroid.SHORT));
        ToastAndroid.showWithGravity('Skills atribuídas com sucesso!', ToastAndroid.TOP, ToastAndroid.SHORT);
        setSkillsAtribuidas([]);
        reload(user.skills);
    }

    return (
        <View style={styles.container}>
            <View style={styles.conteudoModal}>
                <RNPickerSelect
                    onValueChange={handleChange}
                    items={novosObjetos}
                    placeholder={{ label: 'Selecione uma skill', value: null }}
                    style={pickerSelectStyles}
                    value={selectedValue}
                />
                <View style={styles.viewArea}>
                    <ScrollView>
                        {skillsAtribuidas.map((skill: skillLevelType) =>
                            <View style={styles.configurar} key={skill.skill.id}>
                                <View style={styles.nomeArea}>
                                    <FontAwesomeIcon size={15} style={styles.iconeNome} icon={faList} />
                                    <Text style={styles.textWhite}>{handleSubstring(skill)}</Text>
                                </View>
                                <View style={styles.nivelArea}>
                                    <FontAwesomeIcon size={30} style={styles.textWhite} icon={faLongArrowAltUp} />
                                    <TouchableOpacity onPress={() => handleNivel(skill, 'adicionar')}>
                                        <Text style={styles.textWhite}>+</Text>
                                    </TouchableOpacity>
                                    <Text style={styles.textWhite}>{skill.nivel}</Text>
                                    <TouchableOpacity style={styles.botaoDiminuir} onPress={() => handleNivel(skill, "remover")}>
                                        <Text style={styles.textWhite}>-</Text>
                                    </TouchableOpacity>
                                </View>
                                <View>
                                    <TouchableOpacity onPress={() => handleRemoverSkill(skill.skill.id)}>
                                        <FontAwesomeIcon size={25} color='white' icon={faTrash} />
                                    </TouchableOpacity>
                                </View>
                            </View>
                        )}
                    </ScrollView>
                </View>
                <View style={styles.buttonArea}>
                    <TouchableOpacity onPress={handleSalvar} style={styles.botaoAtribuir}>
                        <Text style={styles.textWhite}>Atribuir skills</Text>
                    </TouchableOpacity>
                </View>
            </View>
        </View>
    )
}

const styles = StyleSheet.create({
    container: {
        flex: 1,
        backgroundColor: 'rgba(255, 255, 255, 0.9)', 
        borderRadius: 8,
        padding: 16,
    },
    conteudoModal: {
        backgroundColor: '#ffffff', 
        width: '100%',
        height: 500,
        borderRadius: 8,
        padding: 16,
        borderColor: '#8e44ad', 
        borderWidth: 2,
    },
    botaoAtribuir: {
        justifyContent: 'center',
        alignItems: 'center',
        backgroundColor: '#8e44ad', 
        width: 120,
        height: 35,
        borderRadius: 8, 
    },
    buttonArea: {
        position: 'absolute',
        alignSelf: 'flex-end',
        right: 15,
        bottom: 15,
    },
    viewArea: {
        flexDirection: 'column',
        backgroundColor: 'transparent',
        width: '100%',
        height: '77%',
    },
    configurar: {
        flexDirection: 'row',
        alignItems: 'center',
        marginBottom: 10,
    },
    nomeArea: {
        flexDirection: 'row',
        alignItems: 'center',
        flexGrow: 2,
        width: '40%',
        gap: 5,
    },
    iconeNome: {
        color: '#8e44ad', 
    },
    nivelArea: {
        flexDirection: 'row',
        justifyContent: 'center',
        alignItems: 'center',
        flexGrow: 1,
        gap: 5,
    },
    textWhite: {
        color: '#333', 
    },
    botaoDiminuir: {
        width: 17,
    }
});

const pickerSelectStyles = StyleSheet.create({
    inputIOS: {
        fontSize: 16,
        paddingVertical: 12,
        paddingHorizontal: 10,
        borderWidth: 1,
        borderColor: '#8e44ad', 
        borderRadius: 4,
        color: '#333', 
        paddingRight: 30,
    },
    inputAndroid: {
        fontSize: 16,
        paddingHorizontal: 10,
        paddingVertical: 8,
        borderWidth: 0.5,
        borderColor: '#8e44ad', 
        borderRadius: 8,
        color: '#333', 
        paddingRight: 30,
    },
});
