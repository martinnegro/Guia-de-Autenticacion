import { 
  BrowserRouter as Router, 
  Switch,
  Route
} from 'react-router-dom';
import SignIn from './views/SignIn';
import SignUp from './views/SignUp';
import MyData from './views/MyData';
import './App.css';

function App() {
  return (
    <Router>
      <Switch>
        <Route exact path='/'>
          <SignIn/>
        </Route>
        <Route path='/signup'>
          <SignUp/>
        </Route>
        <Route path='/mydata'>
          <MyData/>
        </Route>
      </Switch>
    </Router>
  );
}

export default App;
