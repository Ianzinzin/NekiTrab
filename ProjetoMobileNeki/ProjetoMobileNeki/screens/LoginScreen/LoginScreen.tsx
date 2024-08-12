import { View, Text, StyleSheet, TouchableOpacity, ToastAndroid } from 'react-native';
import React, { useContext, useEffect, useState } from 'react';
import { TextInput } from 'react-native-gesture-handler';
import { FontAwesomeIcon } from '@fortawesome/react-native-fontawesome';
import { faEye, faUser } from '@fortawesome/free-regular-svg-icons';
import Checkbox from 'expo-checkbox';
import { loginApi } from '../../service/usuario/usuario';
import { LoginScreenNavigationProp, senhaRecType } from '../../interfaces/TypesUsuario';
import { AuthContext } from '../../context/authContext';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { useNavigation } from '@react-navigation/native';

export default function LoginPage() {
  const navigation = useNavigation<LoginScreenNavigationProp>();
  const { salvarUser } = useContext(AuthContext);
  const [email, setEmail] = useState('');
  const [senhaSalva, setSenhaSalva] = useState('');
  const [mostrarSenha, setMostrarSenha] = useState(true);
  const [senha, setSenha] = useState(senhaSalva);
  const [isChecked, setIsChecked] = useState(false);
    
  useEffect(() => {
    const recuperarSenha = async () => {
        try {
            const senhaRecJson = await AsyncStorage.getItem('senha');
            if (senhaRecJson) {
                const senhaRec: senhaRecType = JSON.parse(senhaRecJson);
                const senhaDecodificada = atob(senhaRec.senha);
                setSenhaSalva(senhaDecodificada);                
                setIsChecked(senhaRec.salvar);
                setSenha(senhaDecodificada);
            } else {
                setSenhaSalva(''); 
                setIsChecked(false);
            }
        } catch (error) {
            console.error("Erro ao recuperar a senha:", error);
        }
    };
    recuperarSenha();
  },[]);

  const handleLogin = () => {
    const credenciais = {
        email: email.trim(),
        senha: senha 
    };
    loginApi(credenciais)
    .then((res) =>{
      salvarUser(res.data.usuario);
      AsyncStorage.setItem('token', res.data.token);
      navigation.navigate('Home');
    }).catch((err) =>
      ToastAndroid.show('Não foi possível efetuar login. Verifique os campos.', ToastAndroid.TOP)
    );

    isChecked === true
      ? AsyncStorage.setItem('senha', JSON.stringify({ senha: btoa(senha), salvar: true }))
      : AsyncStorage.setItem('senha', JSON.stringify({ senha: "", salvar: false }));
  };
  
  return (
    <View style={styles.container}>
        <View style={styles.wrapper}>
            <Text style={styles.title}>Login</Text>
            <View style={styles.inputBox}>
                <TextInput 
                  placeholderTextColor='#333' 
                  style={styles.input} 
                  placeholder='Email' 
                  value={email} 
                  onChangeText={setEmail}
                />
                <FontAwesomeIcon style={styles.icone} icon={faUser}/>
            </View>
            <View style={styles.inputBox}>
                <TextInput 
                  placeholderTextColor='#333' 
                  secureTextEntry={mostrarSenha} 
                  style={styles.input} 
                  placeholder='Senha' 
                  value={senha} 
                  onChangeText={setSenha}
                />
                <TouchableOpacity style={styles.botaoIconeSenha} onPress={() => setMostrarSenha(!mostrarSenha)}>
                  <FontAwesomeIcon style={styles.iconeSenha} icon={faEye} />
                </TouchableOpacity>
            </View>

            <View style={styles.lembrarSenha}>
              <Text style={styles.label}>Lembrar senha</Text>
              <Checkbox 
                value={isChecked}
                onValueChange={setIsChecked}
                color={isChecked ? '#8e44ad' : undefined} // Roxo
              />
            </View>

            <TouchableOpacity style={styles.button} onPress={handleLogin}>
                <Text style={styles.buttonText}>Entrar</Text>
            </TouchableOpacity>

            <View style={styles.linkRegistro}>
                <Text style={styles.label}>Ainda não possui uma conta? <Text onPress={() => navigation.navigate('Cadastro')} style={styles.link}>Cadastre-se</Text></Text>
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
    borderRadius: 8, 
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
    borderRadius: 8, 
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
  lembrarSenha: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 20,
  },
  label: {
    color: '#333',
  },
  link: {
    color: '#8e44ad', 
    textDecorationLine: 'underline',
  },
  button: {
    width: '100%',
    height: 50,
    backgroundColor: '#8e44ad', 
    borderRadius: 8, 
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
