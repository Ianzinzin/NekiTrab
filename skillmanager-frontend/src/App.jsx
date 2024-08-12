import { CustomProvider } from 'rsuite';
import AuthProvider from './components/Context/AuthorizarionCont';
import { Rotas } from './routes/Routes';
import 'rsuite/dist/rsuite.min.css';

function App() {
  return (
    <CustomProvider theme="light">
      <AuthProvider>
        <Rotas />
      </AuthProvider>
    </CustomProvider>
  );
}

export default App;
