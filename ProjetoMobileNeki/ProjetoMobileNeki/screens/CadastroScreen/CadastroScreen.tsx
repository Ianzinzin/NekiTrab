import { View, Text, StyleSheet, TextInput, TouchableOpacity, ToastAndroid } from 'react-native';
import React from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-native-fontawesome';
import { faEye, faUser } from '@fortawesome/free-regular-svg-icons';
import { CadastroScreenNavigationProp } from '../../interfaces/TypesUsuario';
import { useNavigation } from '@react-navigation/native';
import { cadastroApi } from '../../service/usuario/usuario';

export default function CadastroPage() {
    const navigation = useNavigation<CadastroScreenNavigationProp>();
    const [email, setEmail] = React.useState('');
    const [senha, setSenha] = React.useState('');
    const [confirmaSenha, setConfirmaSenha] = React.useState('');
    const [mostrarSenha, setMostrarSenha] = React.useState(true);
    const [mostrarConfirmaSenha, setMostrarConfirmaSenha] = React.useState(true);

    const handleCadastro = () => {
        if (email != '' && senha != '' && senha === confirmaSenha) {
            const info = {
                email: email.toLowerCase().trim(),
                senha: senha,
                role: 'ADMIN'
            };
            cadastroApi(info).then((res) => {
                ToastAndroid.showWithGravity('Cadastro Realizado com sucesso', ToastAndroid.SHORT, ToastAndroid.TOP);
                setTimeout(() => {
                    navigation.navigate('Login');
                }, 3000);
            });
        }
    };

    return (
        <View style={styles.container}>
            <View style={styles.wrapper}>
                <Text style={styles.title}>Cadastro</Text>
                <View style={styles.inputBox}>
                    <TextInput
                        placeholderTextColor='#333'
                        style={styles.input}
                        placeholder='Email'
                        value={email}
                        onChangeText={setEmail}
                    />
                    <FontAwesomeIcon style={styles.icone} icon={faUser} />
                </View>
                <View style={styles.inputBox}>
                    <TextInput
                        secureTextEntry={mostrarSenha}
                        style={styles.input}
                        placeholder='Senha'
                        value={senha}
                        onChangeText={setSenha}
                    />
                    <TouchableOpacity
                        style={styles.botaoIconeSenha}
                        onPress={() => setMostrarSenha(!mostrarSenha)}
                    >
                        <FontAwesomeIcon style={styles.iconeSenha} icon={faEye} />
                    </TouchableOpacity>
                </View>
                <View style={styles.inputBox}>
                    <TextInput
                        secureTextEntry={mostrarConfirmaSenha}
                        style={styles.input}
                        placeholder='Confirmar Senha'
                        value={confirmaSenha}
                        onChangeText={setConfirmaSenha}
                    />
                    <TouchableOpacity
                        style={styles.botaoIconeSenha}
                        onPress={() => setMostrarConfirmaSenha(!mostrarConfirmaSenha)}
                    >
                        <FontAwesomeIcon style={styles.iconeSenha} icon={faEye} />
                    </TouchableOpacity>
                </View>
                <TouchableOpacity style={styles.button} onPress={handleCadastro}>
                    <Text style={styles.buttonText}>Cadastrar</Text>
                </TouchableOpacity>
                <View style={styles.linkRegistro}>
                    <Text style={styles.label}>
                        Já possui uma conta? 
                        <Text
                            onPress={() => navigation.navigate('Login')}
                            style={styles.link}
                        >
                            Entrar
                        </Text>
                    </Text>
                </View>
            </View>
        </View>
    );
}

const styles = StyleSheet.create({
    container: {
        flex: 1,
        justifyContent: 'center',
        alignItems: 'center',
        backgroundColor: '#f5f5f5', 
    },
    wrapper: {
        width: 320,
        padding: 20,
        borderRadius: 5, 
        backgroundColor: '#fff', 
        shadowColor: '#000',
        shadowOffset: { width: 0, height: 2 },
        shadowOpacity: 0.2,
        shadowRadius: 8,
        elevation: 5, 
    },
    title: {
        fontSize: 32,
        color: '#333', 
        textAlign: 'center',
        marginBottom: 20,
    },
    inputBox: {
        position: 'relative',
        marginBottom: 20,
    },
    input: {
        width: '100%',
        height: 50,
        backgroundColor: '#f0f0f0', 
        borderColor: '#ccc', 
        borderWidth: 1,
        borderRadius: 5, 
        paddingHorizontal: 15,
        color: '#333', 
    },
    icone: {
        position: 'absolute',
        right: 15,
        top: 15,
        color: '#666', 
    },
    iconeSenha: {
        color: '#666',
    },
    label: {
        color: '#333',
    },
    link: {
        color: '#6a0dad', 
        textDecorationLine: 'underline',
    },
    button: {
        width: '100%',
        height: 50,
        backgroundColor: '#6a0dad', 
        borderRadius: 5, 
        justifyContent: 'center',
        alignItems: 'center',
        marginBottom: 20,
    },
    buttonText: {
        color: '#fff', 
        fontSize: 16,
        fontWeight: 'bold',
    },
    linkRegistro: {
        alignItems: 'center',
    },
    botaoIconeSenha: {
        position: 'absolute',
        alignItems: 'center',
        justifyContent: 'center',
        width: 40,
        height: 40,
        right: 4,
        bottom: 5,
    },
});
