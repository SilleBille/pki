## Build failed
Hey **{{author}}**, 
Thanks for the patch! Unfortunately, something went wrong. Here is the list of transfer.sh URLs to understand the failure:
{{#jobs}}
### {{displayName}}
{{#scripts}}
<details>
  <summary>
    <strong>
    {{command}}
    </strong>
  </summary>
```
{{&contents}}
```
</details>
<br />
{{/scripts}}
{{/jobs}}
NOTE: This comment template is being optimized to improve. Meanwhile, you can check the travis logs for complete info