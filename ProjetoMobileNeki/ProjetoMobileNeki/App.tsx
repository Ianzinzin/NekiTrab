import { StatusBar } from 'expo-status-bar';
import { StyleSheet, Text, View } from 'react-native';
import StackRoutes from './routes/StackRoutes';
import AuthProvider from './context/authContext';

export default function App() {
  return (
      <AuthProvider>
      <StackRoutes/>
      </AuthProvider>
  );
}


