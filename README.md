# Matthew Contaldi's Blog

A personal blog for notes, ideas, projects, and anything else worth sharing.

The Jekyll site is configured for automatic deployment to `https://mdcontaldi.github.io/blog/`.

## Publish on GitHub Pages

1. Create an empty GitHub repository named `blog`.
2. Push this project to its `main` branch:

   ```sh
   git init
   git add .
   git commit -m "chore: initialize repository"
   git branch -M main
   git remote add origin https://github.com/mdcontaldi/blog.git
   git push -u origin main
   ```

3. In the `blog` repository, open **Settings → Pages**.
4. Under **Build and deployment**, set **Source** to **GitHub Actions**.
5. Open **Actions → Deploy Jekyll site to Pages** and choose **Run workflow**. Every later push to `main` rebuilds and deploys the blog automatically.

The workflow gets `/blog` from GitHub Pages at build time, so links and stylesheets work under the project-site path.

## Preview locally

Install Ruby 3.3 and Bundler, then run:

```sh
bundle install
bundle exec jekyll serve --livereload
```

Open <http://localhost:4000/blog/>. The configured `/blog` base path matches the production project-site URL.

## Site configuration

General settings, including the production `url`, are in [`_config.yml`](_config.yml). If the site moves to another GitHub account or a custom domain, update `url` there. For a custom domain, also add a `CNAME` file containing only the domain name.
