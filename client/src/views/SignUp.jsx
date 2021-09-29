import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import axios from 'axios';

const initState = {
    email: '',
    password: ''
}

const SignUp = () => {
    const [ input, setInput ] = useState(initState);

    const handleOnChange = (e) => {
        setInput({
            ...input,
            [e.target.name]: e.target.value
        })
    };

    const handleOnSubmit = (e) => {
        e.preventDefault();
        axios.post('http://localhost:3001/signup',input)
            .then((response)=>{
                alert(response.data.message);
            })
            .catch((response)=>{
                alert(response.data.message);
            })
        setInput(initState);
    }

    return (
        <div>
            <h1>SignUp</h1>
            <form
                onChange={handleOnChange}
                onSubmit={handleOnSubmit}
            >
                <input 
                    value={input.email}
                    name="email"
                    placeholder="Email"
                    type="email"
                />
                <input 
                    value={input.password}
                    name="password"    
                    placeholder="Password"
                    type="password"
                />
                <button type="submit">
                    Registrarse
                </button>
            </form>
            <Link to='/'>
                Ya tengo un cuenta
            </Link>
        </div>
    )
}

export default SignUp