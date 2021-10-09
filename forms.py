from flask_wtf import FlaskForm
from wtforms import *
from wtforms.validators import DataRequired
from wtforms.widgets import PasswordInput


class UserForm(FlaskForm):
    id = IntegerField("Индентификатор")
    username = StringField('Логин', validators=[DataRequired()])
    password = StringField('Пароль', widget=PasswordInput(hide_value=False))

    submit = SubmitField("Войти")

class ChangeUserForm(FlaskForm):
    username = StringField('Логин')
    name = StringField('Имя')
    surname = StringField('Фамилия')

    submit = SubmitField("Изменить")
