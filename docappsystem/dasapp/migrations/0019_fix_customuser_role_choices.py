from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dasapp", "0018_alter_page_mobilenumber"),
    ]

    operations = [
        migrations.AlterField(
            model_name="customuser",
            name="user_type",
            field=models.CharField(
                choices=[
                    ("1", "admin"),
                    ("2", "doc"),
                ],
                default="1",
                max_length=50,
            ),
        ),
    ]