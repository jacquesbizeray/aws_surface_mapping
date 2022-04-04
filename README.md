# aws_surface_monitor
Projeto desenvolvido para fazer a listagem de portas abertas no firewall de máquinas EC2 de contas AWS


# AWS Surface Mapping

<!---Esses são exemplos. Veja https://shields.io para outras pessoas ou para personalizar este conjunto de escudos. Você pode querer incluir dependências, status do projeto e informações de licença aqui--->


<img src="https://ak.picdn.net/shutterstock/videos/1047568495/thumb/1.jpg" alt="exemplo imagem">

> Projeto criado com objetivo de monitoramento de superfície de ataque nas contas na AWS. Esse projeto faz o mapeamento
das portas abertas nas instâncias EC2 em todas as contas AWS que temos.

Arquitetura do Servidor
 * IP: 10.244.29.187
 * Workspace: /home/gitlab-runner/builds
 * Config files: /home/gitlab-runner/data/aws_surface_mapping/aws_surface_mapping.yml
 * Database: /home/gitlab-runner/data/aws_surface_mapping/resultado.db

Para acessar o servidor hospedeiro do projeto procurar alguém da equipe do SOC para configuração do acesso.

### Ajustes e melhorias

O projeto ainda está em desenvolvimento e as próximas atualizações serão voltadas nas seguintes tarefas:

- [x] Ajustar o envio de email
- [ ] Adicionar mais contas para análise


## 💻 Pré-requisitos

Antes de começar, verifique se você atendeu aos seguintes requisitos:
<!---Estes são apenas requisitos de exemplo. Adicionar, duplicar ou remover conforme necessário--->
* Você instalou a versão mais recente de `<linguagem / dependência / requeridos>`
* Você tem uma máquina `<Windows / Linux / Mac>`. Indique qual sistema operacional é compatível / não compatível.
* Você leu `<guia / link / documentação_relacionada_ao_projeto>`.

## 🚀 Instalando AWS Surface Mapping(Local)

Para instalar o AWS Surface Mapping, siga estas etapas:

1. Clone este repositório com o comando: git clone http://gitlab/team/soc/aws_surface_mapping
2. Execute os comandos abaixo no servidor>
$ mkdir /home/gitlab-runner/data/aws_surface_mapping
$ touch /home/gitlab-runner/data/aws_surface_mapping/aws_surface_mapping.yml
2. Execute o script create_schema.py que esta na pasta init dentro do projeto. Este script faz a criação do banco de dados para armazenamento dos achados
3. Ajuste as configurações no arquivo /home/gitlab-runner/data/aws_surface_mapping/aws_surface_mapping.yml
4. Rode o arquivo ec2_monitor.py para fazer o mapeamento

## ☕ Usando AWS Surface Mapping

Para usar AWS Surface Mapping, siga estas etapas acima:

```
<exemplo_de_uso>
```

Adicione comandos de execução e exemplos que você acha que os usuários acharão úteis. Fornece uma referência de opções para pontos de bônus!

## 📫 Contribuindo para AWS Surface Mapping
<!---Se o seu README for longo ou se você tiver algum processo ou etapas específicas que deseja que os contribuidores sigam, considere a criação de um arquivo CONTRIBUTING.md separado--->
Para contribuir com AWS Surface Mapping, siga estas etapas:

1. Clone este repositório.
2. Crie um branch: `git checkout -b <nome_branch>`.
3. Faça suas alterações e confirme-as: `git commit -m '<mensagem_commit>'`
4. Envie para o branch original: `git push origin <nome_do_projeto> / <local>`
5. Crie a solicitação de pull.

Como alternativa, consulte a documentação do GitHub em [como criar uma solicitação pull](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request).

## 🤝 Colaboradores

Agradecemos às seguintes pessoas que contribuíram para este projeto:

<table>
  <tr>
    <td align="center">
      <a href="#">
        <img src="https://miro.medium.com/max/1838/0*lnSH7-BhVs646sfY.jpeg" width="100px;" alt="Foto do Iuri Silva no GitHub"/><br>
        <sub>
          <b>Jacques</b>
        </sub>
      </a>
    </td>
  </tr>
</table>


## 📝 Licença

Esse projeto está sob licença. Veja o arquivo [LICENÇA](LICENSE.md) para mais detalhes.

[⬆ Voltar ao topo](#nome-do-projeto)<br>

