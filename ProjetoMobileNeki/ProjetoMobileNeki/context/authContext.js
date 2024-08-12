import AsyncStorage from "@react-native-async-storage/async-storage";
import React from "react";

export const AuthContext = React.createContext({})

function AuthProvider({ children }) {
    const [user, setUser] = React.useState({});
    const [token, setToken] = React.useState('');

    React.useEffect(() => {
        const loadUser = async () => {
            try {
                const userLocal = await AsyncStorage.getItem('user');
                if (userLocal) {
                    setUser(JSON.parse(userLocal));
                }
            } catch (error) {
                console.error("Failed to load user from storage:", error);
            }
        };

        loadUser();
    }, []);

    React.useEffect(() => {
        if (Object.keys(user).length > 0) {
            AsyncStorage.setItem('user', JSON.stringify(user)).catch(error => {
                console.error("Failed to save user to storage:", error);
            });
        }
    }, [user]);

    console.log(user);
    

    const salvarToken = (token) => {
        setToken(token);
    };

    function salvarUser(usuario) {
        if (usuario) {
            setUser(usuario);
        } else {
            alert("Erro ao salvar informações");
        }
    }

    return (
        <AuthContext.Provider value={{ user, salvarUser, token, salvarToken }}>
            {children}
        </AuthContext.Provider>
    );
}

export default AuthProvider;

