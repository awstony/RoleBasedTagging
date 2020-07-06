const AWS = require("aws-sdk");
const cloudtrail = new AWS.CloudTrail();
const iam = new AWS.IAM();
const ec2 = new AWS.EC2();
const s3 = new AWS.S3();
const zlib = require('zlib');
const dynamodb = new AWS.DynamoDB.DocumentClient();
const resourcegroupstaggingapi = new AWS.ResourceGroupsTaggingAPI();


const assign = {
  resource_name:'',
  event_type:'',
  resource_id: '',
  username: '',
  usertype: '',
  tag_key: '',
  tag_value:''
}

let trackingManifest = [];
let EVENT_NAME_TO_TRACK = '';
let DEFAULT_REGION = '';


const findARN = (obj, value, value2) => {
  let queue = [obj];
  let found = false;
  let result = '';

    while (!found && queue.length) {
      let o = queue.shift();
      found = Object.keys(o).some((k)=> {
        if (k === value || k === value2) {
          result = o[k]
          return true
        };
        if (o[k] !== null && typeof o[k] === 'object') {
          queue.push(o[k])
        }

      })
    }
 return result;
}


exports.handler = async (event ,context) => {

      let records = '';
      let derecord = '';
      let bucketName = await event.Records[0].s3.bucket.name;
      let bucketKey = await event.Records[0].s3.object.key;
      console.log(bucketKey)

    //pull tag Key

     let tparams = {
        TableName: 'Cost_Center_SKU'
    }

    const dynamodbTagPromise = dynamodb.scan(tparams).promise();

    await  dynamodbTagPromise.then((data)=> {
        assign.tag_key = data.Items[0].SKU_Key
        console.log(data.Items[0].SKU_Key)
    }).catch((err)=>{
        console.log(err)
    })

    //pull tracking events

    let dparams = {
        TableName: 'tracking_manifest_rbc'
    }

    const dynamodbPromise = dynamodb.scan(dparams).promise();

    await  dynamodbPromise.then((data)=> {
        trackingManifest = data.Items
        //console.log(trackingManifest)
        EVENT_NAME_TO_TRACK = trackingManifest[0].EVENT_NAME_TO_TRACK
        DEFAULT_REGION = trackingManifest[0].DEFAULT_REGION
    }).catch((err)=>{
        console.log(err)
    })

    //fetch log

    let sparams = {
      Bucket: bucketName,
      Key: bucketKey
    }

    const s3bucketpromise = s3.getObject(sparams).promise();

    await s3bucketpromise.then((data)=> {
      records = data;
      derecord = zlib.unzipSync(data.Body).toString()
      console.log('CloudTrail JSON from S3 decompressed')
    }).catch((err)=>{
      console.log(err)
    });

    //parse unzipped log

    let jsonderecord = JSON.parse(derecord)
    let matchingRecords = jsonderecord.Records


     matchingRecords.forEach(event => {
         trackingManifest.forEach(track => {
             if (event.eventName == track.EVENT_NAME_TO_TRACK && event.awsRegion == track.DEFAULT_REGION) {
                if (event.userIdentity.type == 'IAMUser') {
                    assign.usertype = 'IAMUser';
                    assign.username = event.userIdentity.userName;
                    assign.event_type = event.eventName
                    assign.resource_name = findARN(event, 'instanceId', 'ARN')
                } else if (event.userIdentity.type == 'AssumedRole') {
                    assign.usertype = 'AssumedRole';
                    assign.username = event.userIdentity.sessionContext.sessionIssuer.userName;
                    assign.event_type = event.eventName;
                    assign.resource_name = findARN(event,'instanceId','ARN')
                } else {
                    console.log('No matching user type')
                }
             }
         })
     })

    //pass in username to find cost center tag

     if (assign.usertype == 'IAMUser') {

        let aparams = {
          UserName: assign.username
          }

        let iamPromise = iam.listUserTags(aparams).promise();

           await iamPromise.then((data)=> {
             console.log('Found the cost center tag for this user')
             let tagObject = data.Tags
             let tagAssign = tagObject.filter(tag => tag.Key == assign.tag_key )
             assign.tag_value = tagAssign[0].Value
            }).catch((err)=>{
               console.log(err)
           })
         } else if (assign.usertype == 'AssumedRole') {

           let rparams = {
             RoleName: assign.username
           }

           let iamRolePromise = iam.listRoleTags(rparams).promise();

           await iamRolePromise.then((data)=>{
             console.log('Found the cost center tag for this role')
             let tagObject = data.Tags
             let tagAssign = tagObject.filter(tag => tag.Key == assign.tag_key )
             assign.tag_value = tagAssign[0].Value
           }).catch((err)=>{
             console.log(err)
           })
         }

   //apply cost center tag to created resource

   if(assign.username !== "" || assign.username !== null) {
         if(assign.event_type === 'RunInstances') {
              let params = {
           Resources: [assign.resource_name],
           Tags: [{
               Key: assign.tag_key,
               Value: assign.tag_value
                }]
            }

            let tagCreationPromise = ec2.createTags(params).promise()

            await tagCreationPromise.then((data)=> {
                console.log('Succesfully assigned user tag to resource')
            }).catch((err)=> {
                console.log(err)
            })
            } else {

             let params = {
               ResourceARNList: [assign.resource_name],
               Tags: {
                   [assign.tag_key] : assign.tag_value
               }
            };

            let tagCreationPromise = resourcegroupstaggingapi.tagResources(params).promise()

            await tagCreationPromise.then((data)=> {
                console.log('Succesfully assigned user tag to resource')
            }).catch((err)=> {
                console.log(err)
            })
        }
       } else {
           console.log('Not assignable event')
       }

}
