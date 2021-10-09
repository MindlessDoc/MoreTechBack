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
    role = SelectField(u'Asset type',
                             choices=[('engineer', 'Engineer'),
                                      ('project_manager', 'Project Manager')])

    submit = SubmitField("Изменить")


class DatasetForm(FlaskForm):
    id = IntegerField("Индентификатор")

    name = StringField("Название")
    description = StringField("Описание")

    creation_date = DateField("Дата создания")
    last_change_date = DateField("Дата последнего изменения")

    score = FloatField("Оценка")
    vote_count = IntegerField("Количество оценок")
    views = IntegerField("Просмотры")

    format = StringField("Формат")
    string_count = IntegerField("Количество строк")
    size = StringField("Размер")

    categories = FieldList(IntegerField("Категории"))
    access_role = StringField("Роль для доступа")

    submit = SubmitField("Подтвердить")
