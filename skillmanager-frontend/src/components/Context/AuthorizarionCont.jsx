import React from "react";

export const AuthContext = React.createContext({})

function AuthProvider({children}){
    const [user, setUser] = React.useState(() => {
        const userLocal = localStorage.getItem('user');
        return userLocal ? JSON.parse(userLocal) : {};
      });
      const [token, setToken] = React.useState()

      React.useEffect(()=>{
        if(Object.keys(user).length > 0){
            localStorage.setItem('user', JSON.stringify(user))
        }
      },[user])

      const salvarToken=(token)=>{
        setToken(token)
      }

      function salvarUser(usuario) {
        if (user) {
            setUser(usuario)
            
        }else{
            alert("Erro ao salvar informações")
        }
      }

      return(
        <AuthContext.Provider value={{user,salvarUser,token,salvarToken}}>
            {children}
        </AuthContext.Provider>
      )
}

export default AuthProvider;