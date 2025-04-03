# Generated by Django 4.2.9 on 2025-03-25 11:52

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0005_remove_collector_beach_collector_beaches'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='collector',
            name='beaches',
        ),
        migrations.AddField(
            model_name='collector',
            name='beach',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='collectors', to='core.beach'),
        ),
    ]
