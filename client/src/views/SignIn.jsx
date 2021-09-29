import React, { useState } from 'react'
import { Link, useHistory } from 'react-router-dom';
import axios from 'axios';

const initState = {
    email: '',
    password: ''
}

const SignIn = () => {
    const [ input, setInput ] = useState(initState);
    const history = useHistory()

    const handleOnChange = (e) => {
        setInput({
            ...input,
            [e.target.name]: e.target.value
        })
    };

    const handleOnSubmit = (e) => {
        e.preventDefault();
        axios.post('http://localhost:3001/signin',input)
            .then((response)=>{
                alert(response.data.message);
                console.log(response);
                history.push('/mydata')
            })
            .catch((err)=>{
                alert(err.message)
            });
        setInput(initState)
}

    return (
        <div>
            <h1>SignIn</h1>
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
                    Ingresar
                </button>
            </form>
            <Link to='/signup'>
                Quiero registrarme
            </Link>
        </div>
    )
}

export default SignIn
